# Grayland

Grayland (named after the town of Grayland, Washington) 
is a greylisting milter for the Postfix email server. 
(It is likely compatible with Sendmail as well, but I haven't tested it.)

## What is Greylisting?

Greylisting is a technique for reducing spam emails.
Whenever a message is received from an unfamiliar sender, 
the receiving server returns an error message indicating a temporary failure.
Legitimate mail servers will try again, but many spam senders do not.
So, many spam messages are blocked, but legitimate messages are just delayed a few minutes.

## What is Different About Grayland?

Grayland tries hard not to delay legitimate messages.

 - It doesn't greylist messages from hosts whose reverse-DNS name looks like a mail server.

 - It uses whitelists of legitimate email servers, and doesn't greylist messages from the servers on these lists.
   (The list at dnswl.org is especially helpful. If your mail server isn't on the list, sign up; it's free.)

 - It supports local whitelists as well, with either domain names or IP addresses.

 - If the sender has an SPF result of Pass, the message is not greylisted.

 - It does not have a minimum delay. If the sender retries after one second, the message goes through.

## How Do You Run Grayland?

Grayland expects to be started by inetd, in "wait" mode. 
On my mail server, I have Grayland installed as /usr/local/bin/grayland,
and I have the following line in /etc/inetd.conf:

    :postfix:wheel:660:/var/run/grayland.sock	stream	unix	wait	postfix	/usr/local/bin/grayland	grayland -whitelist /usr/local/etc/postfix/grayland_whitelist

The following line in Postfix's main.cf tells Postfix to use Grayland:

    smtpd_milters = unix:/var/run/grayland.sock

If you already have an `smtpd_milters` line in main.cf, just add Grayland's entry to the start of the list.

Reload inetd and Postfix, and Grayland should be working. 
