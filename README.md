# High-Risk-Tracking-Internal
Tracking Internal Users "High Risk" Activity


Backend data injection
--------------------------------------------------

The goal of it is to use all the log data from the SIEM (graylog) to build a database with the ability to use a tooled UI to use the data from a database, to analyze high risk user activity and give the security team the ability to drop them into High Risk profiles (be it different A/V, HIPS, IPS|IDS, Web Filtering etc), also the abillity to track user risk and report if certain people need more training.

--------------------------------------------------------

The application data used, but could be easily changed to fit different software is:

ESET, Airlock Digital, Malwarebytes, Fortigate + Fortigate Sniffers, planning to add more like sysmon threat hunting queries(the automated obvious ones, of course).

-----------------------------------------------------------

The general idea is getting all the data, filter out the noise: the columns used:

Date, Time, ID, attack, source ip, dest ip, threat, action, country, and a few others. 

Not each column from each source will be filled, but that is ok, we really only want the Where/Who/What of it.

-------------------------------------------------------------

You will need to encrypt your password into a file, and also use your REST api into whatever SIEM you choose, the code should give you the general idea/starting point if you dont use graylog and HIPS/AV/Application Whitelisting tools listed above.


### Sample Screenshot of the database part with some data from ESET and Malwarebytes, but all catagories would have similair info :)

--------------------------------------------------------------------
![image](https://i.imgur.com/EgVbbio.jpg)

## UI
-------------------------------------------------------------------------

Simple UI(# that isn't complete).

Search by Year-Month-Day (from - to) with Sort/Group up IPs, or show only tagged fields

Show all risks - gives everything heads up E.g - second screenshot, you can also sort by IP/tagged fields

#### All results also have criteria search capabilities in the popup.

Export to CSV, options apply to export as well(exports to folder app ran from)

Tracking levels 1/2/3 are used to track a user(ip/workstation).

Level 1 was a "lets watch this user/ip/workstation" say the user has gone to a bad website or opened up spam a few times, but could of been some mistakes.

Level 2 was Level 1 but not innocent or, they need extra training, this would escalate to there manager, etc.

Level 3 was Level 2 but nothing changed and activity gets worse.


The level system also lets you trend/get metrics on a certain user/ip/workstation, to see how for example they got to level 3, or 2, etc. 

---------------------------------------------------------------------------

#### TO BE ADDED
------------------
Disable NIC on $PC
---------------------------
Add to High Risk Profiles for bigger lockdown and filtering (webfilter, IPS/DLP, HIPS, etc)


-----------------------------------------------------------------------
![image](https://i.imgur.com/eyrCq8x.jpg)
![image](https://i.imgur.com/dw1gRry.jpg)
![image](https://i.imgur.com/kUr4hAd.jpg)

