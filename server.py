import socket
import select
import signal
import sys
import threading
import os
import re


class Server:
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # The TCP server socket
    BUFFER_SIZE = 1024  # The size of the buffer to receive data from the server
    MAX_CLIENTS = 5  # The maximum # of concurrently connected clients
    DEFAULT_ENCODING_TYPE = 'utf-8'  # The type of encoding used by data sent and received by the server
    TIME_OUT = 50  # A default length of time in seconds to be set as a time-out period before closing the socket

    def __init__(self, address, port):
        # The dictionary of clients & HTTP REQUESTS
        # KEY: client_socket
        # VALUE: HTTP REQUEST (DATA recv from client)
        self.clients = {}

        self.sockets = []  # List of connected clients

        # Handle a force quit on the server to re-open the
        # previously occupied port
        signal.signal(signal.SIGINT, self.handle_signal)

        # Append this server socket to the client's list
        self.sockets.append(self.server_socket)

        # The server's (address, port) tuple
        self.server = (address, port)

        # Bind the server to this (address, port) tuple
        self.server_socket.bind(self.server)

        # Set the maximum number of concurrent client connections to the server
        self.server_socket.listen(self.MAX_CLIENTS)

        # SET various socket options
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Acknowledge that the server is running and listening
        # for incoming connections
        print("[*] WEB SERVER is listening on: ('%s', %s)" % (address, port))

        # Accept and handle all incoming connections
        self.accept_incoming_connections(self.server_socket)

    def handle_signal(self):
        """Handles when the client forcibly quits or terminates the server"""

        if self.server_socket is not None:
            self.server_socket.close()
            sys.exit(0)

    def accept_incoming_connections(self, server_socket):
        """Handle all incoming connections"""

        while 1:
            print("[!] # of asynchronous clients:", len(self.sockets))

            # Using 'select' obtain the list of 'readable', 'writable', & 'exceptional' sockets
            # using the sockets list
            readable, writable, exceptional = select.select(self.sockets, [], self.sockets, self.TIME_OUT)

            # Make sure there are 'readable' sockets
            if len(readable) > 0:
                # Loop over all readable sockets
                for r in readable:
                    if r == self.server_socket:
                        # ABLE to ACCEPT

                        # Accept the incoming client connection
                        client_socket, address = server_socket.accept()

                        # Acknowledge that an NEW client has connected
                        print("[+] 🖥️ ('%s', %s): has connected" % (address[0], address[1]))

                        # Append this client to the client list
                        if client_socket not in self.sockets:
                            self.sockets.append(client_socket)

                        if client_socket not in self.clients.keys():
                            self.clients[client_socket] = HTTPRequest()
                    else:
                        # ABLE to RECEIVE

                        # Obtain the address used by the client
                        address = r.gethostname()
                        # Obtain the port used by the client
                        port = r.gethostname()[1]

                        # The client's (address, port) tuple
                        client = (address, port)

                        # REBINDING (r) to (client_socket) for readability
                        client_socket = r

                        # Handle the mechanics of this client's request in a thread
                        threading.Thread(target=self.handle_request, args=(client, client_socket)).start()

    def handle_request(self, client, client_socket):
        """Handles the mechanics of a client's request made to this server"""

        # Obtain the HTTP Request from the client dictionary
        request = self.clients[client_socket]

        # Receive the data from the client
        data = client_socket.recv(self.BUFFER_SIZE)

        # Check the size or length of the data received from the client
        if len(data) == 0:
            # If no data exists, then:

            # Acknowledge that this client has disconnected
            print("[-] 🖥️ ('%s', %s): has disconnected" % (client[0], client[1]))

            # Remove this client from the list of concurrently connected clients
            self.sockets.remove(client_socket)

            # Close the client connection
            client_socket.close()
        else:
            # Decode the request received from the client
            data = data.decode(self.DEFAULT_ENCODING_TYPE)

            # Append the data received from the client to the request
            request.append(data)

            # Determine if the HTTP Request is complete
            if request.is_complete():
                # If the HTTP Request is complete, then check its TYPE
                if request.is_get_request():
                    # If the type of the request is 'GET',
                    # Send a GET Request Response back to the client
                    Server.send_get_response(client_socket, request)
                elif request.is_post_request():
                    # If the type of the request is 'POST',
                    # Send a POST Request Response back to the client
                    Server.send_post_response(client_socket, request)

            # Acknowledge that this client has disconnected
            print("[-] 🖥️ ('%s', %s): has disconnected" % (client[0], client[1]))

            # Remove this client from the client dictionary
            del self.clients[client_socket]

            # Remove this client from the list of concurrently connected clients
            self.sockets.remove(client_socket)

            # Close this client's connection
            client_socket.close()

    @staticmethod
    def send_get_response(client_socket, request):
        """Send an HTTP GET REQUEST Response back to the client"""

        # Obtain the URI from the request made by the client
        uri = request.get_uri()

        # Obtain the file-name of the file on the server within
        # the 'static' directory
        file_name = os.path.join('static', uri[1:])

        # Craft an 200, OK response header
        header = HTTPRequest.OK_HEADER

        # Initially set the error boolean to FALSE,
        # since no error has occurred yet in relation
        # to the IO or SOCKET
        error = False

        # Attempt to read the file
        try:
            with open(file_name, "rb") as f:
                line = f.read()  # READ each line of this file

                # Attempt to send an encoded response to the client
                try:
                    # Decode the byte-stream as a 'utf-8' encoded string
                    body = line.decode(Server.DEFAULT_ENCODING_TYPE)

                    # Craft an encoded REPLY to the client
                    reply = (header + body).encode()

                    # Send the REPLY back to the client
                    client_socket.send(reply)
                except socket.error:
                    error = True
        except IOError:
            error = True

        # Check if there was either and IOError or SOCKET error
        if error:
            # If there was an error of some kind:

            # Craft a FILE-NOT-FOUND response header
            header = HTTPRequest.FILE_NOT_FOUND_HEADER

            # Encode the reply
            reply = header.encode()

            # Send the reply back to the client
            client_socket.send(reply)

    @staticmethod
    def send_post_response(client_socket, request):
        """Send an HTTP POST Request Response back to the client"""

        # Obtain the URI from the request made by the client
        uri = request.get_uri()

        # Obtain the file-name of the file on the server within
        # the 'static' directory
        file_name = os.path.join('static', uri[1:])

        # Obtain the content of the HTTP request
        content = request.content

        # The dictionary to contain the KEY, VALUE pairs of the
        # HTTP POST request
        #
        # e.g. ?fn=nick&ln=adamou
        # KEY   = 'fn'
        # VALUE = 'nick'
        data = {}

        # Make sure that content does exist within the request
        if len(content) > 0:
            # Show the content of the request
            print("[!] CONTENT: %s" % content)

            # Split the content on the '&' character
            pairs = content.split('&')

            # Parse the list of pairs
            for pair in pairs:
                # Obtain the KEY, VALUE  pairs, split via the '=' character
                key, value = pair.split('=')

                # Add the KEY & VALUE pair to the data dictionary
                data[key] = value

            # Show the contents of the data dictionary
            print("DATA: %s" % data)

            # Craft the html reply to the client
            html = Server.forge(file_name, data)

            # Craft an 200, OK response header
            header = HTTPRequest.OK_HEADER

            # Encode the reply
            reply = header.encode()

            # Encode the html response
            html = html.encode()

            # Send the reply back to the client
            client_socket.send(reply)

            # Send the HTML back to the client
            client_socket.send(html)

    @staticmethod
    def forge(file_name, data):
        """
        Forges the HTML file to send back to the client
        when the client sends an HTTP POST Request to
        the server
        """

        # The modified file to be returned as a payload
        # to be sent back to the client
        file = ''

        # Generate a regex pattern using 're'
        regex = re.compile(r'{{[a-zA-Z0-9]+}}')

        # Open the passed 'file_name'
        with open(file_name, 'r') as f:
            line = f.read()  # Read a line from this file

            while 1:
                # Using the regex, search the line and return any matches
                matches = regex.search(line)

                # If there isn't any matches, then break
                if matches is None:
                    break
                else:
                    # Obtain a (start, end) index tuple of the list of matches
                    start, end = matches.span()

                    # Obtain the key from the list of matches using the 'start' & 'end' range
                    key = line[start + 2:end - 2]

                    # Check if the key exists within the data dictionary
                    if key in data:
                        # Obtain the value linked to the key in the data dictionary
                        value = data[key]
                    else:
                        # The key the client inputted into the form, does not contain any known
                        # value, thus, set the value to '{{UNKNOWN}}'
                        value = "{{UNKNOWN}}"

                    # Show that the key & value has been found
                    print("[!] FOUND KEY, VALUES: ('%s', %s)" % (key, value))

                    # Put the value within the line of the opened file
                    file = line[0:start] + value + line[end:]

        # Return the modified file as a string to be used as a payload
        # to be sent back to the client
        return file


class HTTPRequest:
    # The 200, OK response header
    OK_HEADER = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
    # The 404, File Not Found response header
    FILE_NOT_FOUND_HEADER = "HTTP/1.1 404 File Not Found\r\n\r\n<html><h1>File Error</h1></html>"

    def __init__(self):
        """
          request -- contains the requested string
          bad_request -- is set to be true if there is a problem with the header
          type -- None, GET, or POST. It is either GET or POST when it is complete
          has_header -- the header is complete

        """

        self.request = ""  # The request itself
        self.header = ""  # The header of the request
        self.content = ""  # The content of the request

        self.header_values = {}  # The list of values passed via a POST request
        self.action = None  # The list of actions
        self.bad_request = False  # Whether or not the request is a bad request
        self.type = None  # The type of request

        self.has_header = None  # Whether or not the request has a header
        self.content_length = -1  # The length of the data passed via a POST request

    def append(self, data):
        """Appends the passed 'data' to the request"""

        # Append the 'passed' data to the request
        self.request += data

        # Check if this request has a type
        if self.type is None:
            # If this request does not have a type, obtain it by
            # checking the length of the request string
            if len(self.request) > 4:
                if self.request[:3] == "GET":
                    self.type = "GET"
                elif self.request[:4] == "POST":
                    self.type = "POST"
                else:
                    self.bad_request = True

            # Show that a type exists for this request
            print("[!] FOUND TYPE: %s" % self)

        # Check if the request does not have a header
        if self.has_header is None:
            # Grab the index to the end of the header
            index = self.request.find('\r\n\r\n')

            # If the value of the 'index' is greater than 0,
            # then more data exists
            if index > 0:
                # Obtain the header of the request based off of the above index
                self.header = self.request[:index]

                # obtain each line of the header by splitting the header on each 'new-line' character
                lines = self.header.split('\n')

                # Obtain a list of actions from each line
                self.action = lines[0]

                # Obtain the content of the request
                self.content = self.request[index + 4:]

                # Loop over each line of the header
                for line in lines[1:]:
                    # Split each line into a list containing the KEY, VALUE pair of each header item
                    # e.g. KEY:   Cookie
                    #      VALUE: Webstorm-ea36d52b=7cf702c4-f920-40c7-acfd-a25b1d77b36c
                    data = line.split(':')

                    # Obtain the KEY
                    key = data[0]
                    # The VALUE associated with the KEY
                    value = ':'.join(data[1:])
                    value = value.strip()

                    # If the request is a 'POST' request
                    # then, it contains the header, 'Content-Length'
                    # This refers to the length of the data passed by
                    # the POST request to the server
                    if key == 'Content-Length':
                        # Obtain the length of the data passed by the POST request
                        # to the server
                        self.content_length = int(value)

                    self.header_values[key] = value

                # SET the 'has_header' to true indicating that this request NOW
                # has a header
                self.has_header = True

            # Show the processed request
            print('[!] PROCESSED REQUEST: %s' % self)
        else:
            # If the request DOES have a header, append the data to
            # the content of this request
            self.content += data

    def get_uri(self):
        """Returns the URI of the request"""

        (action, uri, http_version) = self.action.split(' ')

        return uri

    def is_bad(self):
        """Determines if the request is a bad request, e.g. 404, NOT-FILE-FOUND"""

        return self.bad_request

    def is_complete(self):
        """Determines if the request is a complete request based on its type"""

        if self.type == 'GET' and self.has_header:
            return True

        if self.type == 'POST' and self.content_length == len(self.content):
            return True

        return False

    def is_get_request(self):
        """Determines if the request is a 'GET' Request"""

        return self.type == 'GET'

    def is_post_request(self):
        """Determines if the request is a 'POST' Request"""

        return self.type == 'POST'

    @staticmethod
    def parse(request):
        """
        Parses an HTTP GET request
        Returns the URI
        """

        # Show the HTTP REQUEST
        print("[!] HTTP REQUEST:\n------------\n%s\n------------" % request)

        # Obtain the (action, URI, HTTP-Version #) from the request
        action, uri, http_version = request.split('\n')[0].split(' ')

        # Return the URI of the request
        return uri

    def __str__(self):
        """Returns a stringified representation of this request"""

        return 'type=%s complete=%s bad=%s content_length=%d/%d' % (self.type, self.is_complete(), self.is_bad(),
                                                                 len(self.content), self.content_length)


if __name__ == "__main__":
    Server('127.0.0.1', 8080)
