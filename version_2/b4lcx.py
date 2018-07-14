import argparse
import asyncio
import base64
import hashlib
import hexdump
import logging
import random
import struct

cmd_chap,cmd_bind,cmd_conn,cmd_data, = range(4)
cmd_dict = {0:'chap', 1:'bind', 2:'conn', 3:'data'}
listen_conn_id_last = 0

async def wait_conn_event(event):
    await event.wait()

async def listen_do_client(reader, writer):
    peer_host, peer_port, = writer.get_extra_info('peername')
    sock_host, sock_port, = writer.get_extra_info('sockname')
    log.info('S L R<C open {:5} < {:5}'.format(sock_port, peer_port))

    reader_for_slave, writer_for_slave, = listen_bind_dict[sock_port]

    global listen_conn_id_last
    listen_conn_id_last += 1
    conn_id = listen_conn_id_last

    msg_send('R', writer_for_slave, 'BHS', cmd_conn, conn_id, b'1')

    conn_event = asyncio.Event()
    listen_conn_dict[conn_id] = reader_for_slave, writer, conn_event

    try:
        await asyncio.wait_for(wait_conn_event(conn_event), 40)
    except Exception as e:
        log.warning('S L R>C shut {:5} > {:5} exc {}'.format(sock_port, peer_port, e.args))
        listen_conn_dict.pop(conn_id, None)
        writer.close()
        return

    while True:
        data = await raw_recv('R', reader, writer) 
        if not data:
            break
        msg_send('R', writer_for_slave, 'BHS', cmd_data, conn_id, data)

    if not conn_id in listen_conn_dict:
        return
    msg_send('R', writer_for_slave, 'BHS', cmd_conn, conn_id, b'0')
    listen_conn_dict.pop(conn_id, None)


async def listen_do_slave(reader, writer):
    peer_host, peer_port, = writer.get_extra_info('peername')
    sock_host, sock_port, = writer.get_extra_info('sockname')
    log.info('S L>R C open {:5} < {:5}'.format(sock_port, peer_port))

    salt = str(random.randint(100000,999999)).encode('utf8')
    msg_send('R', writer, 'BS', cmd_chap, salt)

    err, cmd, username, digest, = await msg_recv('R', reader, writer, 'BSS', cmd_chap)
    if err:
        return

    if not listen_user_dict.get(username, None):
        log.error('S L<R C shut {:5} > {:5} error username {}'.format(sock_port, peer_port, username))
        writer.close()
        return

    if digest != base64.b64encode(hashlib.md5(username + listen_user_dict[username] + salt).digest()):
        log.error('S L<R C shut {:5} > {:5} error digest {}'.format(sock_port, peer_port, digest))
        writer.close()
        return

    err, cmd, bind_port = await msg_recv('R', reader, writer, 'BH', cmd_bind)
    if err:
        return

    server = None
    try:
        coro = asyncio.start_server(listen_do_client, '0.0.0.0', bind_port, loop=loop)
        server = await asyncio.wait_for(asyncio.ensure_future(coro), None)
        bind_port = server.sockets[0].getsockname()[1]
 
        listen_bind_dict[bind_port] = reader, writer

        msg_send('R', writer, 'BH', cmd_bind, bind_port)
    except Exception as e:
        log.error('S L<R C shut {:5} < {:5} bind_port {} exc {}'.format(sock_port, peer_port, bind_port, e.args))
        writer.close()
        return

    while True:
        err, cmd, conn_id, data = await msg_recv('R', reader, writer, 'BHS', cmd_conn, cmd_data)
        if not err:
            reader_for_slave, writer_for_client, conn_event, = listen_conn_dict.get(conn_id, (None,None,None))
            if not writer_for_client:
                continue
            if reader_for_slave != reader: ## !!! important
                log.error('S L<R C shut {:5} > {:5} conn_id {} error'.format(sock_port, peer_port, conn_id))
                writer.close()
                err = True
        if err:
            close_list = [(conn_id, reader_for_slave, writer_for_client) for conn_id, (reader_for_slave, writer_for_client, conn_event) in listen_conn_dict.items()]
            for (conn_id, read_for_slave, writer_for_client) in close_list:
                if reader_for_slave == reader:
                    writer_for_client.close()
                    listen_conn_dict.pop(conn_id, None)
            listen_bind_dict.pop(bind_port)
            server.close()
            await server.wait_closed()
            return

        client_host, client_port, = writer_for_client.get_extra_info('peername')
        if cmd == cmd_conn:
            listen_conn_dict[conn_id][2].set()
            state = int(data)
            if not state:
                log.info('S L R>C shut {:5} > {:5}'.format(bind_port, client_port))
                listen_conn_dict.pop(conn_id, None)
                writer_for_client.close()
        elif cmd == cmd_data:
            raw_send('R', writer_for_client, data)
    

async def msg_recv(role, reader, writer, fmt, *expect_cmds):
    direct_dict = {'L':'<', 'R':'>'}
    direct = direct_dict[role]
    result =[True]
    result.extend([None for x in fmt])

    peer_host, peer_port, = writer.get_extra_info('peername')
    self_host, self_port, = writer.get_extra_info('sockname')

    msg = None
    try:
        data = await reader.readexactly(2)
        if not data:
            log.error('S L{}R C recv {:5} < {:5} err EOF msg_len'.format(direct, self_port, peer_port))
            writer.close()
            return result
        msg_len, = struct.unpack('!H', data)
        if not msg_len:
            log.error('S L{}R C recv {:5} < {:5} err ZERO msg_len'.format(direct, self_port, peer_port))
            writer.close()
            return result

        msg = await reader.readexactly(msg_len)
        if not msg:
            log.error('S L{}R C recv {:5} < {:5} err EOF msg_body'.format(direct, self_port,  peer_port))
            writer.close()
            return result
        if not msg[0] in expect_cmds:
            log.error('S L{}R C recv {:5} < {:5} err cmd {} expect {}'.format(direct, self_port, peer_port, msg[0], expect_cmds))
            writer.close()
            return result
    except Exception as e:
        log.warning('S L{}R C shut {:5} < {:5} exc {}'.format(direct, self_port, peer_port, e.args))
        writer.close()
        return result

    unpack_dict = {'B':1, 'H':2}
    pos = 0
    try:
        for i,c in enumerate(fmt):
            if c == 'S':
                s_len, = struct.unpack('!H', msg[pos:pos+2])
                pos += 2
                s_val, = struct.unpack('!{}s'.format(s_len), msg[pos:pos+s_len])
                pos += s_len
                result[i+1] = s_val
            else:
                v_len = unpack_dict[str(c)]
                v_val, = struct.unpack('!' + str(c), msg[pos:pos+v_len])
                pos += v_len
                result[i+1] = v_val
    except Exception as e:
        log.error('S L{}R C recv {:5} < {:5} exc {}'.format(direct, self_port, peer_port, e.args))
        writer.close()
        return

    log.info('S L{}R C {} {:5} < {:5} {}'.format(direct, cmd_dict[msg[0]], self_port, peer_port, result[2:]))
    result[0] = False
    return result

def msg_send(role, writer, fmt, *args):
    direct_dict = {'L':'>', 'R':'<'}
    direct = direct_dict[role]

    peer_host, peer_port, = writer.get_extra_info('peername')
    self_host, self_port, = writer.get_extra_info('sockname')

    log.info('S L{}R C {} {:5} > {:5} {}'.format(direct, cmd_dict[args[0]], self_port, peer_port, args[1:]))

    struct_fmt = '!'
    struct_args = []
    for i,c in enumerate(fmt):
        if c == 'S':
            struct_fmt += 'H{}s'.format(len(args[i]))
            struct_args.extend([len(args[i]), args[i]])
        else:
            struct_fmt += str(c)
            struct_args.append(args[i])

    data = struct.pack(struct_fmt, *struct_args)
    msg = struct.pack('!H', len(data)) + data
    writer.write(msg)


async def raw_recv(role, reader, writer):
    direct_dict = {'L':('>',' '), 'R':(' ','<')}
    direct = direct_dict[role]

    peer_host, peer_port, = writer.get_extra_info('peername')
    self_host, self_port, = writer.get_extra_info('sockname')

    data = None
    try:
        data = await reader.read(65530) ## max data_content is 65528 = 65535 - 1(cmd) - 2(conn_id) -2(data_len)
        if not data:
            log.info('S{}L R{}C shut {:5} < {:5}'.format(direct[0], direct[1], self_port, peer_port))
            writer.close()
            return
    except Exception as e:
        log.error('S{}L R{}C shut {:5} < {:5} exc {}'.format(direct[0], direct[1], self_port, peer_port, e.args))
        writer.close()
        return
    log.info('S{}L R{}C recv {:5} < {:5} {}'.format(direct[0], direct[1], self_port, peer_port, data))
    return data


def raw_send(role, writer, data):
    direct_dict = {'L':('<',' '), 'R':(' ','>')}
    direct = direct_dict[role]

    peer_host, peer_port, = writer.get_extra_info('peername')
    self_host, self_port, = writer.get_extra_info('sockname')

    log.info('S{}L R{}C send {:5} < {:5} {}'.format(direct[0], direct[1], self_port, peer_port, data))
    writer.write(data)


async def slave_do_listen(remote_host, remote_port, username, password, local_host, local_port, bind_port=0):
    reader, writer = await asyncio.open_connection(remote_host, remote_port, loop=loop)
    sock_host, sock_port = writer.get_extra_info('sockname')
    log.info('S L>R C open {:5} > {:5}'.format(sock_port, remote_port))
    err, cmd, salt = await msg_recv('L', reader, writer, 'BS', cmd_chap)
    if err:
        return

    msg_send('L', writer, 'BSS', cmd_chap, username, base64.b64encode(hashlib.md5(username + password + salt).digest()))
    msg_send('L', writer, 'BH', cmd_bind, bind_port)

    err, cmd, bind_port = await msg_recv('L', reader, writer, 'BH', cmd_bind)
    if err:
        return

    while True:
        err, cmd, conn_id, data = await msg_recv('L', reader, writer, 'BHS', cmd_conn, cmd_data)
        if err:
            continue
        writer_for_server = slave_conn_dict.get(conn_id, None)
        if cmd == cmd_conn:
            state = int(data)
            if state:
                if not writer_for_server:
                    loop.create_task(slave_do_server(local_host, local_port, conn_id, writer))
                # else:
                #     log.error('S L>R C shut {:5} > {:5} conn_id {} state {} error conn_id'.format(sock_port, remote_port, conn_id, state))
                #     writer.close()
                #     return
            elif writer_for_server:
                self_host, self_port, = writer_for_server.get_extra_info('sockname')
                log.info('S<L R C shut {:5} > {:5}'.format(self_port, local_port))
                slave_conn_dict.pop(conn_id, None)
                writer_for_server.close()
            # else:
            #     log.error('S L>R C shut {:5} > {:5} conn_id {} state {} error conn_id'.format(sock_port, remote_port, conn_id, state))
            #     writer.close()
            #     return
                
        elif cmd == cmd_data:
            if not writer_for_server:
                # log.error('S L>R C shut {:5} > {:5} conn_id {} data_len {} error conn_id'.format(sock_port, remote_port, conn_id, len(data)))
                # writer.close()
                msg_send('L', writer, 'BHS', cmd_conn, conn_id, b'0')
                continue
            raw_send('L', writer_for_server, data)


async def slave_do_server(local_host, local_port, conn_id, writer_for_listen):
    sock_port = '-----'
    speer_host, speer_port, = writer_for_listen.get_extra_info('peername')
    slave_host, slave_port, = writer_for_listen.get_extra_info('sockname')

    log.info('S<L R C conn {:5} > {:5}'.format(sock_port, local_port))
    try:
        reader, writer = await asyncio.open_connection(local_host, local_port, loop=loop)
        sock_host, sock_port, = writer.get_extra_info('sockname')
        log.info('S<L R C open {:5} > {:5}'.format(sock_port, local_port))
        msg_send('L', writer_for_listen, 'BHS', cmd_conn, conn_id, b'1')
        slave_conn_dict[conn_id] = writer
        while True:
            data = await raw_recv('L', reader, writer)
            if not data:
                break
            msg_send('L', writer_for_listen, 'BHS', cmd_data, conn_id, data)
    except Exception as e:
        log.warning('S<L R C conn {:5} > {:5} exc {}'.format(sock_port, local_port, e.args))

    if conn_id in slave_conn_dict:
        slave_conn_dict.pop(conn_id, None)
        msg_send('L', writer_for_listen, 'BHS', cmd_conn, conn_id, b'0')


# log_fmt = logging.Formatter('%(lineno)-3d %(levelname)7s %(funcName)-16s %(message)s')
log_fmt = logging.Formatter('%(lineno)-3d %(levelname)7s %(message)s')
log_handler = logging.StreamHandler()
log_handler.setLevel(logging.DEBUG)
log_handler.setFormatter(log_fmt)
log = logging.getLogger(__file__)
log.addHandler(log_handler)
log.setLevel(logging.DEBUG)

parser = argparse.ArgumentParser(description='asyncio lcx demo.')
subparsers = parser.add_subparsers(dest='mode', help='mode help')

parser_listen = subparsers.add_parser('listen', help='listen mode help')
parser_listen.add_argument('-p', dest='port', required=True, type=int, help='Port listend for slave side')
parser_listen.add_argument('-u', dest='users', required=True, help='Users in format username:password[,...]') ## nargs?

parser_slave = subparsers.add_parser('slave', help='slave mode help')
parser_slave.add_argument('-b', dest='bind', type=int, default=0, help='Bind port in remote listen default 0')
parser_slave.add_argument('-l', dest='local', required=True, help='Local server address in slave mode when got CONNECT_REQ')
parser_slave.add_argument('-r', dest='remote', required=True, help='Remote listen address in format host:port')
parser_slave.add_argument('-u', dest='user', required=True, help='User in format username:password')

args = parser.parse_args()
log.info('='*40)

listen_bind_dict = dict()  ## key:bind_port val:reader_for_slave, writer_for_slave
listen_conn_dict = dict()  ## key:conn_id   val:reader_for_slave, writer_for_client
listen_user_dict = dict()  ## key:username  val:password

loop = asyncio.get_event_loop()

slave_conn_dict = dict() ## key:conn_id val:(reader_for_server, writer_for_server)

if args.mode == 'listen':
    listen_user_dict = {k.encode('utf8'):v.encode('utf8') for k,v in (x.split(':',1) for x in args.users.split(','))}
    coro = asyncio.start_server(listen_do_slave, '0.0.0.0', args.port, loop=loop)
    server = loop.run_until_complete(coro)
    log.info('S L:R C bind {:5}'.format(args.port))
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    server.close()
    loop.run_until_complete(server.wait_closed())
elif args.mode == 'slave':
    local_host, local_port = args.local.split(':', 1)
    remote_host, remote_port = args.remote.split(':', 1)
    username, password = args.user.split(':', 1)
    try:
        loop.run_until_complete(slave_do_listen(remote_host, remote_port, username.encode('utf8'), password.encode('utf8'), local_host, local_port, args.bind))
    except KeyboardInterrupt:
        pass
else:
    parser.print_help()

loop.close()
