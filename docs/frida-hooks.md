# Frida Hooks
This folder contains the Frida hooks used by NoMoATS.
They JavaScript from these two files is compiled into a single file 
([nomoats_agent.js](../nomoats/resources/nomoats_agent.js)) via Node.JS. If you need to change the hooks,
you will need to re-compile the final file with the steps provided below.

## Compiling Frida Hooks
You will need Node.JS.
First, change to a directory where you want to keep your Node.JS modules.
For example, your home directory. We will refer to this directory as
`<NODE_HOME>`.
  ```
  $ cd <NODE_HOME>
  $ sudo apt-get install npm
  $ sudo npm install -g n
  $ sudo n stable
  $ sudo npm install frida-compile@8.0.1
  $ sudo npm install frida-java@2.0.8
  $ cd <NoMoATS_HOME>/nomoats/frida_hooks
  $ <NODE_HOME>/node_modules/.bin/frida-compile java_hooks.js -o frida_agent.js
  ```

The last command from above will output `frida_agent.js`, which is the compiled script you can use
to replace [nomoats_agent.js](nomoats/resources/nomoats_agent.js).
