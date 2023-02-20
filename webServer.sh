#! usr/bin/bash
cd server
node webServer.js --svIndex $1
exec bash