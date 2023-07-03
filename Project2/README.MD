execution steps for ss7495_ping.py:
** This program needs to be run on a Windows machine**(Do not run on MAC)
Steps:
1.Open the file in pycharm.
2.Right click and select modify configurations.
3.Enter the parameters like:
ping www.google.com 
ping www.google.com -t 5 -c 4(wait time is 5 and count is 4 packets to be sent)
ping.www.google.com -c 4(4 packets will be sent)
And the same procedure for the rest of the filters too. 
Multiple filters is also supported with this program.

execution steps for ss7495_traceroute.py:
** This program needs to be run on a MAC Laptop or MAC mini **(Do not run on windows)
Steps:
1.Open the file in pycharm.
2.Right click and select modify configurations.
3.Enter the parameters like:
traceroute www.google.com 
traceroute www.google.com -q 3(sets the number of probes)
traceroute www.google.com -n(prints hop address numerically)
traceroute.www.google.com -S 1(Please note that the value should be given after the -S 1)
And the same procedure for the rest of the filters too. 
Multiple filters is not supported with this program.


Please reach out to me at ss7495@g.rit.edu if any issues arises.