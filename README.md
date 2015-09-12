FCatalog Client (IDA Plugin)
============================

This is the FCatalog Client IDA Plugin.
FCatalog is the Functions Catalog. It is a tool for quickly finding similar
functions from a large database of functions.

You can find the [fcatalog_server repository here](https://github.com/xorpd/fcatalog)

Requirements:
-------------

- You need IDA (Interactive Disassembler by Hex Rays) installed. I tested this
  only on IDA of version >= 6.

- Python2.7. I think that it should come together with IDA. Note that this code
  will not work with Python3. Sorry about that, IDA doesn't support Python3
  scripting yet.

- I tested this only on Windows 7. It might work on linux, but also might not.


Installation
------------
Copy the fcatalog_client directory and fcatalog_plugin.py to the plugins
directory of your IDA installation. Then restart IDA.

Main Functions
--------------

After the installation, when you open any file with IDA you should see new menu
items under the **Edit** menu: 
- FCatalog: Clean IDB
- FCatalog: Find Similars
- FCatalog: Commit Functions
- FCatalog: Configure

First, configure your client by clicking on **FCatalog: Configure**. A dialog
box will ask you for the host and port of your FCatalog server. You will also
need to specify a database name. You can pick any database name that you want.
If it does not exist, it will be created automatically.

**FCatalog: Commit Functions** will save all your good "reversed" functions into
the remote database. Functions are considered good and "reversed" if all of the
following are true:

- They have a meaningful name (Any name that doesn't contain MAYBE or RELATED)
- They weren't acquired from a previous 'FCatalog: Find Similars' operation.
- They are long enough (At least 0x40 bytes) 
- They are not fragmented (Might be implemented in the future).

The IDA console should show you which functions were sent to the database.

**FCatalog: Find Similars** will search for every "unreversed" function inside
your IDB the most similar known function from the functions catalog database.
It will then rename the function according to the name from the functions
catalog database.

The new name will be of the format:
FCATALOG__{grade}__{function_name}
grade is the similarity score, between 0 and 16. 0 means not similar at all, 16
means very similar.

"unreversed functions" are functions that don't have any meaningful name, or
they have a name picked by the fcatalog system.

**FCatalog: Clean IDB** will clean your IDB from any fcatalog function names.
If you suddenly got scared from all the new function names, you can always
click on this button.


Tests
-----
There are basic offline tests in the test directory. You can run them with
unittest as follows:

        c:\python27\python.exe -m unittest discover


There is one online test (Runs against a real server). It is
tests/live_server.py. It should be run as follows:

        c:\python27\python.exe -m fcatalog_client.tests.live_server <host> <port>

Website
-------
Visit me at http://www.xorpd.net
