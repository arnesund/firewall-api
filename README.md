# Firewall API
A JSON API for firewall rules, to answer questions like "Is this traffic permitted or denied?". Implemented as a WSGI app in Python with the Flask framework.

## About

The Firewall API can answer the following requests:
 - What firewalls and ACLs does the traffic pass from source to destination?
 - Is the traffic permitted or denied by this specific firewall ACL?

A client can utilize this functionality to check end-to-end access by first quering for the path from source to destination, and then query if the traffic is permitted by each hop in that path.

This repository includes two example clients that both use the API:
 - A web client based on Flask, in "webapp.py" (plus templates and static files)
 - A command line client in "client/check_firewalls.py", written in Python

This project was initially a Hackathon-2015 project at MET Norway.
