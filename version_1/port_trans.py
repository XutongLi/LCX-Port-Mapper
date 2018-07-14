import asyncio
from sys import argv
import time
import random
import os


#----------------------------------Local Slave---------------------------------------------------
#连接的协程
async def tcp_echo_client(loop):
    while True:
        try:
            reader, writer = await asyncio.open_connection(s_ip_remote_listen, int(s_port_remote_listen), loop=loop)
            break
        except ConnectionRefusedError:
            r = await asyncio.sleep(0.05) #未连接继续查询，每0.1秒查一次
    
    global s_write_to_remote
    s_write_to_remote = writer
    global s_read_from_remote
    s_read_from_remote = reader

    #接收到chap_salt消息
    data = await reader.readexactly(40)
    chap_salt = data.decode('utf-8')
    print("[Get Chap_salt] -- " + chap_salt)
    command = chap_salt.split('|')[1]
    salt = chap_salt.split('|')[2]
    #如果传送正确
    if command == "01":
        print("[Result] -- chap_salt is right!")

        #发送chap_hash
        username_len = len(s_username)
        hash_len = len(s_password)+ len(salt)
        mess_len = len("02") + len(str(username_len)) + len(s_username) + len(str(hash_len)) + len(salt) + len(s_password)
        chap_hash = str(mess_len) + "|02|" + str(username_len) + "|" + s_username + "|" + str(hash_len) + "|" + salt + s_password + "|"
        chap_hash = chap_hash.ljust(40)
        writer.write(chap_hash.encode('utf-8'))
        print("[Sent to Remote] -- chap_hash is sent!")

        #接收chap_result
        data = await reader.readexactly(40)
        chap_result = data.decode('utf-8')
        print("[Get Chap_result] -- " + chap_result)
        command = chap_result.split('|')[1]
        #判断传送是否正确
        if command == "03":
            print("[Result] -- chap_result is right!")

            #发送bind_request消息
            request_id = "id"
            mess_len = len("11") + len(request_id) + len(s_port_remote_open)
            bind_request = str(mess_len) + "|11|" + request_id + "|" + s_port_remote_open + "|"
            bind_request = bind_request.ljust(40)
            writer.write(bind_request.encode('utf-8'))
            print("[Sent to Remote] -- bind_request is sent!")

            #接收bind_response
            data = await reader.readexactly(40)
            bind_response = data.decode('utf-8')
            print("[Get Bind_response] -- " + bind_response)
            command = bind_response.split('|')[1]
            if command == "12":
                print("[Result] -- bind_response is right!")

                #启动协程
                coroutine_read = read_data_from_remote()
                coroutine_connect = []
                for i in range(101):
                    coroutine_connect.append(connect_to_server())
                tasks = [asyncio.ensure_future(coroutine_read)]
                for i in range(101):
                    tasks.append(asyncio.ensure_future(coroutine_connect[i]))
                await asyncio.wait(tasks)

            else:
                print("[Result] -- bind_response is wrong!")
                writer.close()
        else:
            print("[Result] -- chap_result is wrong!")
            writer.close()
    else:
        print("[Result] -- chap_salt is wrong!")
        writer.close()


#Local Slave 从 Remote Listen 接收信息的协程
async def read_data_from_remote():
    while True:
        data = await s_read_from_remote.readexactly(40)
        data_get = data.decode('utf-8')
        command = data_get.split('|')[1]
        if command == "21":     #connect request
            port_get = data_get.split('|')[3]
            print("[Connection request] -- Connect to port " + port_get) 
            #向连接队列中添加
            s_connect_port_buffer.append(port_get)

        elif command == "30":    #data
            connect_id = data_get.split('|')[2]
            port_get = connect_id.split('_')[1]
            info_get = data_get.split('|')[4]
            idx = 0
            if len(s_port_collect):
                idx = s_port_collect.index(port_get)
            msg = info_get
            s_write_to_server[idx].write(msg.encode('utf-8'))

        elif command == "40":   #disconnect
            connect_id = data_get.split('|')[2]
            port_get = connect_id.split('_')[1]
            idx = s_port_collect.index(port_get)
            print("[Disconnect] -- client " + port_get)
            s_write_to_server[idx].close()    #关闭和server连接
            
        else:   #消息错误，关闭TCP连接
            for w in s_write_to_server:
                w.close()

            


#连接向local server的协程
async def connect_to_server():
    while True:
        if len(s_connect_port_buffer):
            connect_port = s_connect_port_buffer.pop(0)
            try:
                reader, writer = await asyncio.open_connection(s_ip_local_server, int(s_port_local_server))
            except ConnectionRefusedError:  #连接失败，发送失败的connect response
                ran = str(random.randint(1000,9999))
                connect_id = ran + "_" + connect_port
                #将connect_response添加到发送队列
                length = len("22") + len("id") + len("fail") + len(connect_id)
                connect_response = str(length) + "|22|id|fail|" + connect_id + "|"
                connect_response = connect_response.ljust(40)
                s_write_to_remote.write(connect_response.encode('utf-8'))
                await s_write_to_remote.drain()
                break
            s_port_collect.append(connect_port)
            s_write_to_server.append(writer)
            idx = s_port_collect.index(connect_port)
            ran = str(random.randint(1000,9999))
            connect_id = ran + "_" + connect_port
            #将connect_response添加到发送队列
            length = len("22") + len("id") + len("success") + len(connect_id)
            connect_response = str(length) + "|22|id|success|" + connect_id + "|"
            connect_response = connect_response.ljust(40)
            s_write_to_remote.write(connect_response.encode('utf-8'))
            await s_write_to_remote.drain()
            
            while True:
                try:
                    data = await reader.read(100)
                    data_get = data.decode('utf-8')
                    if data_get == "":  #此处断开Local Slave到Local server的连接后,server会向slave发送""，所以要避免这一问题
                        writer.close()
                        length = len("40") + len(connect_id)
                        data_send = str(length) + "|40|" + connect_id + "|"
                        data_send = data_send.ljust(40)
                        s_write_to_remote.write(data_send.encode('utf-8'))
                        await s_write_to_remote.drain()
                        print("[Disconnect] -- Local Server which is connected to " + str(connect_port))
                        flag_connect = False
                        break
                    else:
                        data_len = len(data_get)
                        connect_port = s_port_collect[idx]
                        length = len("30") + len(str(data_len))+ len(connect_id) + len(data_get)
                        data_send = str(length) + "|30|" + connect_id + "|" + str(data_len) + "|" + data_get + "|"
                        data_send = data_send.ljust(40)
                        s_write_to_remote.write(data_send.encode('utf-8'))
                        await s_write_to_remote.drain()
                except ConnectionResetError :
                    break
        r = await asyncio.sleep(0.05)    #每0.1秒查询一次

#---------------------------------------------------------------------------------------------

#-----------------------------------Remote Listen------------------------------------------

async def handle_echo(reader, writer):
    global l_write_to_slave
    l_write_to_slave = writer

    global l_read_from_slave
    l_read_from_slave = reader

    addr = writer.get_extra_info('peername')
    print('\nAccept new connection from %s:%s...' % addr)

    #发送Chap-salt消息
    salt = str(random.randint(1111, 5555))
    mess_len = len("01") + len(salt)
    chap_salt = str(mess_len) + "|01|" + salt + "|"
    chap_salt = chap_salt.ljust(40)
    writer.write(chap_salt.encode('utf-8'))
    await writer.drain()
    print("[Sent to Slave] -- chap_salt is sent!")

    #接收chap_hash
    data = await reader.readexactly(40)
    chap_hash = data.decode('utf-8')
    print("[Get Chap_hash] -- " + chap_hash)
    command = chap_hash.split('|')[1]
    #判断是否正确
    if command == "02":
        #验证用户名与密码
        username_get = chap_hash.split('|')[3]
        password_get = chap_hash.split('|')[5][4:]
        exist = True
        if username_get in l_username_list:
            index = l_username_list.index(username_get)
            if password_get == l_password_list[index]:
                exist = True    #用户存在
            else:
                exist = False
        else:
            exist = False
        if exist == True:
            print("[Result] -- chap_hash is right!")

            #发送chap_result
            mess_len = len("03") + len("success")
            chap_result = str(mess_len) + "|03|success" +"|"
            chap_result = chap_result.ljust(40)
            writer.write(chap_result.encode('utf-8'))
            await writer.drain()
            print("[Sent to Slave] -- chap_result is sent!")

            #接收bind_request
            data = await reader.readexactly(40)
            bind_request = data.decode('utf-8')
            print("[Get Bind_request] -- " + bind_request)
            command = bind_request.split('|')[1]
            #验证是否正确
            if command == "11":
                print("[Result] -- bind_request is right!")

                #获取端口
                listen_port = bind_request.split('|')[3]
                if listen_port == '0':  #如果是0，在合理范围内随机指定
                    listen_port = str(random.randint(1025, 6666))

                #发送bind_response消息
                request_id = bind_request.split('|')[2]
                result = "success"
                mess_len = len("12") + len(request_id) + len(result) + len(listen_port) 
                bind_response = str(mess_len) + "|12|" + request_id + "|success|" + listen_port + "|"
                bind_response = bind_response.ljust(40)
                writer.write(bind_response.encode('utf-8'))
                await writer.drain()
                print("[Sent to Slave] -- bind_response is sent!")

                #监听8001、接收发送消息的协程
                remomte_listen_tasks = []
                remomte_listen_tasks.append(asyncio.start_server(listen_remote_client, '127.0.0.1', int(listen_port)))
                remomte_listen_tasks.append(asyncio.ensure_future(get_data_from_slave()))
                print('[Listen a new port] -- Serving on {}'.format(listen_port))
                await asyncio.wait(remomte_listen_tasks)

            else:
                print("[Result] -- bind_request is wrong!")
                writer.close()
        else:
            print("[Result] -- username or password is wrong!")
            writer.close()
    else:
        print("[Result] -- chap_hash is wrong!")
        writer.close()

#产生新的连接的协程
async def listen_remote_client(reader, writer):
    addr = writer.get_extra_info('peername')
    print('\n[Remote Client] -- Accept connection from %s:%s...' % addr)
    localhost, connect_port = addr

    l_port_collect.append(connect_port)
    l_write_to_client.append(writer)  #这两者的index一样
    l_connection_id.append("none")    #此时还没id
    idx = l_port_collect.index(connect_port)
    l_judge_response.append(False)

    #将connect_request添加到发送队列
    request_id = "id"
    result = "success"
    mess_len = len("21") + len(request_id) + len(str(connect_port))
    connect_request = str(mess_len) + "|21|" + request_id + "|" + str(connect_port) + "|"
    connect_request = connect_request.ljust(40)
    l_write_to_slave.write(connect_request.encode('utf-8'))
    await l_write_to_slave.drain()

    while True:
        if l_judge_response[idx]:
            try:
                #接收来自remote client的消息
                data = await reader.read(100)
                data_get = data.decode('utf-8')
                if data_get == "": 
                    writer.close()
                    length = len("40") + len(l_connection_id[idx])
                    data_send = str(length) + "|40|" + l_connection_id[idx] + "|"
                    data_send = data_send.ljust(40)
                    l_write_to_slave.write(data_send.encode('utf-8'))
                    await l_write_to_slave.drain()
                    print("[Disconnect] -- cliet " + str(connect_port))
                    break
                else:
                    data_len = len(data_get)
                    length = len("30") + len(str(data_len))+ len(l_connection_id[idx]) + len(data_get)
                    data_send = str(length) + "|30|" + l_connection_id[idx] + "|" + str(data_len) + "|" + data_get + "|"
                    data_send = data_send.ljust(40)
                    l_write_to_slave.write(data_send.encode('utf-8'))
                    await l_write_to_slave.drain()

            except ConnectionResetError:    #断开连接
                break
        else:
            r = await asyncio.sleep(0.05)
            

#Remote Listen从local slave接收信息的协程
async def get_data_from_slave():
    continue_flag = True
    while True:
        data = await l_read_from_slave.readexactly(40)
        data_get = data.decode('utf-8')
        command = data_get.split('|')[1]
        if command == "22": #connect response
            print("[Get Connect Response] -- " + data_get)
            result = data_get.split('|')[3]
            if result == "success": #连接成功
                connect_id = data_get.split('|')[4]
                port_get = connect_id.split('_')[1]
                idx = l_port_collect.index(int(port_get))
                l_connection_id[idx] = connect_id
                l_judge_response[idx] = True
            else:   #连接失败
                connect_id = data_get.split('|')[4]
                port_get = connect_id.split('_')[1]
                idx = l_port_collect.index(int(port_get))
                l_connection_id[idx] = connect_id
                print("[Get Connection_response] -- the connection of port " + port_get  + " is failed\n")
                #失败后关掉连接
                l_write_to_client[idx].close()

        elif command == "30":   #data
            connect_id = data_get.split('|')[2]
            port_get = connect_id.split('_')[1]
            idx = l_port_collect.index(int(port_get))
            info_get = data_get.split('|')[4]
            msg = info_get
            l_write_to_client[idx].write(msg.encode('utf-8'))
            await l_write_to_client[idx].drain()

        elif command == "40":    #disconnect
            connect_id = data_get.split('|')[2]
            port_get = connect_id.split('_')[1]
            idx = l_port_collect.index(int(port_get))
            print("[Disconnect] -- Local Server which is connected to " + port_get)
            l_write_to_client[idx].close()    #关闭和server连接

        else:   #消息错误，关闭TCP连接
            for w in l_write_to_client:
                w.close()

#------------------------------------------------------------------------------------------

m = argv.index('-m')
mode = argv[m+1]

if mode == "slave":		#local slave
	r = argv.index('-r')
	u = argv.index('-u')
	p = argv.index('-p')
	l = argv.index('-l')

	#Remote Listen 向内的监听
	s_ip_remote_listen = argv[r+1].split(':')[0]
	s_port_remote_listen = argv[r+1].split(':')[1]

	#用户名和密码
	s_username = argv[u+1].split(':')[0]
	s_password = argv[u+1].split(':')[1]

	#Local server的监听地址
	s_ip_local_server = argv[l+1].split(':')[0]
	s_port_local_server = argv[l+1].split(':')[1]

	#需要Remote Listen开启的端口，可设为0
	s_port_remote_open = argv[p+1]

	s_write_to_remote = None      #向Remote Listen发送消息的StreamWriter
	s_read_from_remote = None     #从Remote Listen接收信息的StreamReader
	s_port_collect = []           #Remote Client已连接的port的集合
	s_write_to_server = []        #向Local Server发送消息的StreamWriter集合
	s_connect_port_buffer = []    #还未连接上的port的集合


	loop = asyncio.get_event_loop()
	loop.run_until_complete(tcp_echo_client(loop))
	loop.close()
	
elif mode == "listen":	#remote listen
	#接收命令行输入
	p = argv.index('-p')
	u = argv.index('-u')

	#指定向内的监听端口
	l_port = argv[p+1]
	l_user_list = argv[u+1].split(',')
	l_username_list = []  #有户名列表
	l_password_list = []  #密码列表，两者通过index联系
	for user in l_user_list:
	    l_username_list.append(user.split(':')[0])
	    l_password_list.append(user.split(':')[1])

	l_port_collect = []       #当前已
	l_write_to_client = []    #向Remote Client发送消息的StreamWriter的集合
	l_connection_id = []      #进行通信的id的集合
	l_judge_response = []
	l_write_to_slave = None   #向Local Slave发送消息的StreamWriter
	l_read_from_slave = None  #从Local Slave接收消息的StreamWriter



	loop = asyncio.get_event_loop()
	#监听端口8000
	coro = asyncio.start_server(handle_echo, '127.0.0.1', int(l_port), loop = loop)
	server = loop.run_until_complete(coro)


	print('Serving on {}'.format(server.sockets[0].getsockname()))
	try:
	    loop.run_forever()
	except KeyboardInterrupt:
	    pass

	# Close the server
	server.close()
	loop.run_until_complete(server.wait_closed())
	loop.close()
else:
	print("wrong input")

os.system('pause')
