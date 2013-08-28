smf_1-1_bridge_wp_3-5
=====================

Bridging the 1.1.x version of Simple Machines forum with Wordpress 3.5

This wordpress plugin is based on the wp-smf-bridge plugin located on the [Wordpress plugin directory](http://wordpress.org/plugins/wp-smf-bridge/)

Original README
===============

=== Plugin Name ===
Contributors: jonnyfunfun
Donate link: http://code.google.com/p/wp-smf-bridge/
Tags: smf,forums,users,bridge
Requires at least: 2.8.6
Tested up to: 2.9.2
Stable tag: 0.3.1

User registration and login bridge between Wordpress and Simple Machine Forum

== Description ==

WP-SMF-Bridge is a simple user registration and logon bridge between Wordpress and Simple Machine Forum.  To get this working, it is highly recommended that you have a fresh, unmodified install of SMF 1.1 or higher installed and running alongside an install of WordPress.  It must be installed in a subdirectory under your WP install and should not be being accessed through a sumdomain.  For example, if your website's address is mysite.mydomain.com, your forums should be somewhere like mysite.mydomain.com/myforum.  Also, Wordpress must be able to access your SMF configuration files, otherwise it won't work!

Please do keep in mind that this is a new plugin, and has not been thoroughly tested yet - and should probably not be used on a production website!  I am not responsible for any data loss that might occur through your use of this plugin!  Please see the plugin's website for a bug-tracker and bug reporting system!  If you find a problem, let me know about it so that it may be fixed.  If you want to see a feature added, let me know about it so that I may add it!

== Installation ==

Obviously, you need to have a SimpleMachine Forum installation working. It is preferred to have the forum installed as a subdirectory within your WordPress install. For example, if you access your blog from www.mydomain.com, it is preferred for you to access your forum at www.mydomain.com/forum. The name of the directory does not matter, but your forum and WordPress installations should not be on different domains or subdomains! Your blog on www.mydomain.com and forum on forum.mydomain.com will not work!

The databases do not need to be the same between the forum and WordPress installs, nor do the database users, but it is highly recommended for performance that you do so.

From that point forth, configuration is rather simple - all you need to do is install the plugin and enter the relative path to your forum install. In the above example, a WordPress install on www.mydomain.com and forums on www.mydomain.com/forum, the relative path would simply be forum/. Do not add a leading slash, and the trailing slash is optional - the plugin will assume one should be there if you do not explicitly add it.

If this is a new install, you're all set. If this is not a new install, you will probably want to synchronize your users. Please note that synchronizing your users on a site that is not a new install is not recommended, as it has the potential to completely mess up your user accounts. For more information on this process, refer to SynchronizingUsers on the Google Code website.  If you have an existing WordPress site, but a fresh SMF install, you should have no issues with synchronizing users - the main problem comes when you try to synchronize both SMF and WordPress user tables together.

== Frequently Asked Questions ==

= I need help or found a bug! =

Go here and tell me about it:
http://code.google.com/p/wp-smf-bridge

= How do I acheive X? =

Read above.

= I would really like feature X, can you add it? =

Read above; a pattern emerges ;)
