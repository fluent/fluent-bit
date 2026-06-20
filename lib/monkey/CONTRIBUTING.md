# Contributing to Monkey Project

We build Open Source software and we invite everyone to join us and contribute. So if you are interested into participate, please refer to the guidelines below.

## GIT Repositories

All code changes and submissions happens on [Github](http://github.com), that means that to start contributing you should clone the target repository, perform local changes and then do a Pull Request. For more details about the workflow we suggest you check the following documents:

 - https://help.github.com/articles/using-pull-requests
 - https://help.github.com/articles/creating-a-pull-request

## Coding Style

Our development coding style for C is based on the Apache C style guidelines, we use the same rules, to get more details about it please check the following URL:

 - https://httpd.apache.org/dev/styleguide.html

You have to pay attention to the code indentation, tabs are 4 spaces, spaces on conditionals, etc. If your code submission is not aligned, it will be rejected.

## Commit Changes

When you commit your local changes in your repository (before to push to Github), we need you take care of the following:

 - Your principal commit message (one line subject) must be prefixed with the core section name, e.g: If you are adding a new but missing protocol feature it could be __HTTP: add new XYZ method__.
 - The Subject of the commit must not be longer than 80 characters.
 - On the commit body, each line should not be longer than 80 characters.
 - On most of cases we want full description about what your patch is doing, the patch description should be self descriptive.. like for dummies. Do not assume everybody knows what you are doing and on each like do not exceed 80 characters.
 - When running the __git commit__ command, make sure you are using the __-s__ flag, that will add a Signed-off comment in the patch description.

Expanding a bit the example feature message we could use the following command:

> $ git commit -a -s
>
> HTTP: add new XYZ method
>
> This patch adds the missing XYZ method described in RCF2616 in the
> section 12.4.x.a, it do not alter the core behavior but if the new
> method is requested it will take care of the proper handling.
>
> the patch have been tested using tools A & B.
>
> Signed-off-by: Your Name <your@email.com>

If you want to see a real example, run the following command:

> $ git log 4efbc11bafeb56fbe2b4f0f6925671630ce84125

Your path/patches should be fully documented, that will make the review process faster for us, and a faster merge for you.

## Code review, no feelings

When we review your code submission, they must follow our coding style, the code should be clear enough, documented if required and the patch Subject and Description well formed (within others).

If your code needs some improvement, someone of the reviewers or core developers, will write a comment in your Pull Request, so please take in count the suggestion there, otherwise your request will never be merged.

Despite the effort that took for you to create the contribution, that is not an inditacion that the code have to be merged into upstream, everything will be reviewed and must be aligned as the code base.

## Community and respect

Beside code, we are a community. Respect between all of us is mandatory, so we encourage to keep a good vocabulary on all our communication channels, as well we don't accept any discrimination by gender, sexual orientation, religion or other. Make sure you also contribute to keep a good environment.
