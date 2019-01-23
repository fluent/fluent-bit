# Contribution Guidelines for Fluent-Bit

We build Open Source software and we invite everyone to join us and contribute. So if you are interested into participate, please refer to the guidelines below.

## GIT Repositories

All code changes and submissions happens on [Github](http://github.com), that means that to start contributing you should clone the target repository, perform local changes and then do a Pull Request. For more details about the workflow we suggest you check the following documents:

 - https://help.github.com/articles/using-pull-requests
 - https://help.github.com/articles/creating-a-pull-request

## Coding Style

Our development coding style for C is based on the Apache C style guidelines, we use the same rules, to get more details about it please check the following URL:

 - https://httpd.apache.org/dev/styleguide.html

You have to pay attention to the code indentation, tabs are 4 spaces, spaces on conditionals, etc. If your code submission is not aligned, it will be rejected.

## Licensing

[Fluent-Bit](http://fluentbit.io) is an Open Source project and all it code base _must_ be under the terms of the [Apache License v2.0](http://www.apache.org/licenses/LICENSE-2.0). When submitting changes to the core or any new plugin, you agreed to share that code under the license mentioned. All your source code files must have the following header:

```
/*
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
```

Despite some licenses can be compatible with Apache, we want to keep things easy and clear avoiding a mix of Licenses across the project.

## Commit Changes

When you commit your local changes in your repository (before to push to Github), we need you take care of the following:

 - Your principal commit message (one line subject) must be prefixed with the core section name, e.g: If you are adding a new but missing protocol feature it could be __Engine: fix handling of ABC__.
 - The Subject of the commit must not be longer than 80 characters.
 - On the commit body, each line should not be longer than 80 characters.
 - On most of cases we want full description about what your patch is doing, the patch description should be self descriptive.. like for dummies. Do not assume everybody knows what you are doing and on each line do not exceed 80 characters.
 - When running the __git commit__ command, make sure you are using the __-s__ flag, that will add a Signed-off comment in the patch description.

Expanding a bit the example feature message we could use the following command:

> $ git commit -a -s
>
> Engine: fix handling of ABC.
>
> This patch fix a problem when managing the flush buffer of ABC output plugin. It adds
> a new routines to check proper return values and validate certain exceptions.
>
> the patch have been tested using tools A & B.
>
> Signed-off-by: Your Name <your@email.com>

If you want to see a real example, run the following command:

> $ git log dfff256eca7ad38dd94c9838fef272c99a3fffec

Your patches should be fully documented. That will make the review process faster for us and a faster merge for you.

## Code review, no feelings

When we review your code submission, they must follow our coding style, the code should be clear enough, documented if required and the patch Subject and Description well formed (within others).

If your code needs some improvement, someone of the reviewers or core developers, will write a comment in your Pull Request, so please take in count the suggestion there, otherwise your request will never be merged.

Despite the effort that took for you to create the contribution, that is not an inditacion that the code have to be merged into upstream, everything will be reviewed and must be aligned as the code base.
