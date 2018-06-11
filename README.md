# High-Risk-Tracking-Internal
Tracking Internal Users "High Risk" Activity

#### The UI for this is still being made, will update later.

Backend data injection
--------------------------------------------------

The goal of it is to use all the log data from the SIEM (graylog) to build a database with the ability to use a tooled UI to use the data from a database, to analyze high risk user activity and give the security team the ability to drop them into High Risk profiles (be it different A/V, HIPS, IPS|IDS, Web Filtering etc), also the abillity to track user risk and report if certain people need more training.

--------------------------------------------------------

The application data used, but could be easily changed to fit different software is:

ESET, Airlock Digital, Malwarebytes, Fortigate + Fortigate Sniffers

-----------------------------------------------------------

The general idea is getting all the data, filter out the noise: the columns used:

Date, Time, ID, attack, source ip, dest ip, threat, action, country, and a few others. 

Not each column from each source will be filled, but that is ok, we really only want the Where/Who/What of it.

-------------------------------------------------------------

You will need to encrypt your password into a file, and also use your REST api into whatever SIEM you choose, the code should give you the general idea/starting point if you dont use graylog and HIPS/AV/Application Whitelisting tools listed above.


### Sample Screenshot of the database part with some data from ESET and Malwarebytes, but all catagories would have similair info :)

--------------------------------------------------------------------
![image](https://i.imgur.com/EgVbbio.jpg)
