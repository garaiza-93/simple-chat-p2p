#Gustavo Araiza, CS4390.
#P2P - a node that needs to act as both a server and client
#The server thread listens for connections and receives messages
#The client thread connects to a peer and sends messages

import socket
import threading
import sys
import os
import select
import time
import traceback
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox

###OPTIONS###
PORT = 50001
#############

def validIP(ipaddr):
    try:
        socket.inet_aton(ipaddr)
    except:
        return False
    return True

class App():

    def __init__(self, master):
        #reference to TkInter window
        self.master = master
        #window elements
        self.master.title('Amazing Chat App')
        self.make_ip_bar() #top bar to input peer's IP
        self.make_receive_log() #text box that displays incoming messages
        self.make_send_log() #text box that displays outgoing messages
        self.make_message_bar() #bottom bar to input chat messages
        #initialize socket to send messages
        self.write_socket_startup()
        #indicates if the socket has been opened before
        self.isRetry=0

        #overide X button functionality
        self.master.protocol("WM_DELETE_WINDOW", self.on_exit)


    def server(self):
        listenSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #set up socket, use IPv4
        #listenSock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        with listenSock:
            listenSock.bind(("0.0.0.0", PORT)) #reachable from all interfaces
            self.receive_log.insert(tk.INSERT, "Waiting for connection...\n")
            listenSock.listen()
            peer, addr = listenSock.accept()
            with peer: #Using connection data:
                self.receive_log.insert(tk.INSERT, f'Connection from: {addr[0]}\n') #Print their address
                while True:
                    message = peer.recv(2048) #get message from socket
                    if not message: #When a peer disconnects
                        self.receive_log.insert(tk.INSERT, f'DISCONNECTED: {addr[0]} \n') #Inform user that peer disconnected
                        self.connect_button['state'] = tk.NORMAL
                        self.send_button['state'] = tk.DISABLED
                        self.writeSock.close()
                        break
                    self.receive_log.insert(tk.INSERT, f'{addr[0]}> {message.decode()}\n') #Print peer's address and message

    def client(self, peerIP):
        try:
            self.send_log.insert(tk.INSERT, f"Attempting connection to {peerIP}...\n")
            self.writeSock.connect((peerIP, PORT)) #Try to connect to peer at specified port.
            self.send_log.insert(tk.INSERT, f"Connected to {peerIP}!\n")
            self.send_button['state'] = tk.NORMAL
        except: #If an error occurred, print traceback
            self.send_log.insert(tk.INSERT, f"{traceback.print_exc()}\n")

    def make_ip_bar(self):
        self.ip_bar = ttk.Frame(self.master)

        #configuration for grid placement
        self.ip_bar.columnconfigure(0, weight=1)
        self.ip_bar.columnconfigure(1, weight=10)
        self.ip_bar.columnconfigure(2, weight=7)

        #label that tells what the input field is for
        self.label = ttk.Label(self.ip_bar, text="Peer IPv4:")
        self.label.grid(column=0,row=0,sticky=tk.W, padx=1)

        #input field
        self.ipaddr = tk.StringVar()
        self.input_field = ttk.Entry(self.ip_bar, textvariable=self.ipaddr, width=61)
        self.input_field.grid(column=1, row=0, sticky=tk.EW, padx=1)

        #button that starts connection
        self.connect_button = ttk.Button(self.ip_bar, text="Connect", command=self.start_connect)
        self.connect_button.grid(column=2, row=0, sticky=tk.E, padx=1)

        #attach ip_bar to window
        self.ip_bar.grid(column=0, row=0, sticky=tk.NSEW, padx=3, pady=3)

    def make_receive_log(self):
        self.receive_log = tk.Text(self.master)
        self.receive_log.grid(column=0, row=1, sticky=tk.W, padx=5, pady=3)

    def make_send_log(self):
        self.send_log = tk.Text(self.master)
        self.send_log.grid(column=1, row=1, sticky=tk.E, padx=5, pady=3)

    def make_message_bar(self):
        self.message_bar = ttk.Frame(self.master)
        #configuration for grid placement
        self.message_bar.columnconfigure(0, weight=1)
        self.message_bar.columnconfigure(1, weight=10)
        self.message_bar.columnconfigure(2, weight=1)

        #label
        self.chat_label = ttk.Label(self.message_bar, text= "Chat:")
        self.chat_label.grid(column=0, row=0, sticky=tk.W, padx=3, pady=3)

        #input field
        self.sendMsg = tk.StringVar()
        self.send_input = ttk.Entry(self.message_bar, textvariable=self.sendMsg, width=61)
        self.send_input.grid(column=1, row=0, sticky=tk.EW, padx=3, pady=3)

        #button
        self.send_button = ttk.Button(self.message_bar, text="Send", command=self.send_msg)
        self.send_button['state'] = tk.DISABLED #start disabled
        self.send_button.grid(column=2, row=0, sticky=tk.E, padx=3, pady=3)

        #attach message bar to window
        self.message_bar.grid(column=1, row=2, sticky=tk.E, padx=5, pady=5)

    def write_socket_startup(self):
        #socket to send msgs
        self.writeSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #Set up socket, use IPv4
        self.writeSock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def start_connect(self):
        if self.isRetry == 1:
            self.refresh_write_socket()
        else:
            self.isRetry = 1
        peerip = self.ipaddr.get()
        self.receive_log.delete(1.0, "end")
        self.send_log.delete(1.0, "end")

        if validIP(peerip): #if this is an IPv4 address...
            self.connect_button['state'] = tk.DISABLED #prevent further input
            server_thread = threading.Thread(target=self.server)
            client_thread = threading.Thread(target=self.client, args=(peerip, ))
            server_thread.start()
            client_thread.start()
        else:
            self.ipaddr.set("")
            messagebox.showerror(title='Invalid IPv4 Address', message='Enter a valid IPv4 address!')

    def send_msg(self):
        msg = self.sendMsg.get()
        if msg:
            self.writeSock.sendall(bytes(msg, 'utf-8')) #Send message
            self.send_log.insert(tk.INSERT, f"{msg}\n")
        self.sendMsg.set("")

    def refresh_write_socket(self):
        self.writeSock.close()
        self.write_socket_startup()

    def on_exit(self):
        self.writeSock.close()
        os._exit(0)

if __name__ == "__main__": #Start chat app
    root = tk.Tk()
    app = App(root) #Root window
    root.mainloop()
