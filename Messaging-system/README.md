
# Demo instructions
1. pip3 install -r requirements. 
2. Flask Run
3. Navigate to 127.0.0.1:5000
4. Register a new user and login


# Features
* Instant messages between user accounts.
* A sender and one recepient
* Sends a message with some content, can reply to the same message
* A read /unread inbox with timestamp using MomentJS and Flask-moment. 
* Delete messages / all messages in that conversation

# Code analysis
* Comments in code app.py


# Security Considerations
* Authentication
  Web sockets do not perform any authentication. Even if you do have authentication in place, it is still possible to performe som esort of MITM attack, simply by modefing the clinet-sice javascript to try to intercept event channels that should not be accessed. These channels are unprotected, so if someone gets the event channel ID. its easy to eavesdrop.
  If authentication on the socket is required, it should be done via a cookie or token in the header, or passed as an argument during the connection.

  his application will listen for specific events emitted to the random string ID for the messaging thread. Once the socket detects the emitted event it understands that a new messages has arrived for that thread, from a regular Ajax request is sent to get the new message data. By using ajax. we can perform full server-side authentication of the client to verify its identity before sending any data back. In this way, if we somehow obtain a randomly generated ID and attempt to sniff a particular event channel, we will only see notifications of new incoming messages. Hence, no sensitive information will be exposed.

* Cross Origin Resource Sharing
  The Flask-SocketIO library used has built-in CORS support. This will prevent external websites from accessing the websocket and potentially using server resources.

# Questions
* Threat model – who might attack the application? What can an attacker do? What damage could be done (in terms of confidentiality, integrity, availability)? Are there limits to what an attacker can do?  Are there limits to what we can sensibly protect against?
    * Typical attackers might be unathorized users which is a threat to the confidentiality and the integrity as the attacker is not welcome. Also if the attacker gains access to the database they can     modify or delete the database. Something like this will threaten the availibilty as authorized can not longer log in to the web application. To protect the database, its important to have a backup stored locally. 

* What are the main attack vectors for the application?
    * The main attack vectors for this application is sql injections. This is a huge cyber risk as the database stores username, password and private messages. Attackers gain unauthorized access to the system and steal sensitive data or modify the data. 

* What should we do (or what have you done) to protect against attacks?
    * The only sure way to prevent sql attacks is with input validation and parametrized quieris including prepared statements. The application code should never use the input directly. 

* What is the access control model?
    * The access control model enables you to control the ability of a process to access securable objects or to preform various system administration tasks. 

* How can you know that you security is good enough? (traceability)
    * One way to ensure good enough security and data traceability is to complete a study beginning to end on a closed system or platform. Some other factors for good security is: Logging and backup. Applications write event log data to the filesystem or a database, and have a backup of the last safe-known state. 

