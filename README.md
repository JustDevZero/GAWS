**Google Amazon Wrapper Single sign on**

Or just `gaws` it's a wrapper that allows you to run aws commands.

Either aws cli scripts or any aws sdk along a collection of multiple accounts.

This is really usefull when you're something like a hosting provider and have servers along different accounts.

By using this you won't need to authenticate by your self multiple times as it will do it automatically for you.

It's important that your accounts are onboared in the Google Single Sign On service.

**Important Data**

You will need to know Google's assigned Identity Provider ID, and the ID that they assign to the SAML service provider.

Once you've set up the SAML SSO relationship between Google and AWS, you can find the SP ID by drilling into the Google Apps console, under Apps > SAML Apps > Settings for AWS SSO -- the URL will include a component that looks like ...#AppDetails:service=123456789012... -- that number is GOOGLE_SP_ID

You can find the GOOGLE_IDP_ID, again from the admin console, via Security > Set up single sign-on (SSO) -- the SSO URL includes a string like https://accounts.google.com/o/saml2/idp?idpid=aBcD01AbC where the last bit (after the =) is the GOOGLE_IDP_ID.



* Free software: BSD license
* For Python 3.6+
* Changelog: https://github.com/JustDevZero/GAWS/releases
* Code, issues, tests: https://github.com/JustDevZero/GAWS
*

This project uses https://github.com/cevoaustralia/aws-google-auth under the hood.


----

**HOW TO INSTALL IT?**

First of all, make sure to have *AWS CLI* installed:

https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html


After it, make sure to dedicate a virtualenv only for GAWS so it won't mess up with whatever you have on your system.


Create a virtualenv for python3.6 onwards, we tried with 3.9 and it worked like a charm:

```virtualenv --python /usr/bin/python3.9  ~/.virtualenvs/gaws```

```source ~/.virtualenvs/gaws/bin/activate```

```python -m pip install GAWS```

Now, add symbolic link somewhere in your path *gaws* command, for example:

```ln -s ~/.virtualenvs/gaws/bin/gaws ~/.local/bin/gaws```

----

**How to use it?**

It's easy as fuck, just navigate into the example folder, copy the gaws.ini file into the folder of your project.

If you can, you can grab the inventory_instances.py to test it as an example if you want too.

Then, all you have to do, is go to that folder in your terminal and edit gaws.ini and fill it according your needs.

For example:

```cd ~/Projects/MyScriptCollection```

```emacs gaws.ini ## or vim gaws.ini ## or.. nano gaws.ini...```

 Now instead of executing the script as your normally could do, prefix it with `gaws`, see the following:

```gaws python inventory_access.py```

If you run gaws for first time, it will show you a wizard to fill with default parameters, that are going yo be stored on ~/.gaws/config.ini

And that's it, it will crawl the ini file and execute inventory_access.py against each one of the accounts.

