<pre>
A secure Instant Messaging (IM) system that satisfies the vital security features by leveraging UDP sockets in the client-server communication model.


pip install rsa 
pip install hashlib
pip install pycryptodome

python server.py
python client.py
    Enter Clients username (Format: CLIENT<username>)
    In this step, client gets authenticated. Gets the list of available clients from the server

python client.py
    Enter Clients username (Format: CLIENT<username>)
    Select the client to communicate and server will respond with the selected client's details (Format: @<username>)
    Communication between the clients is initiated
</pre>
