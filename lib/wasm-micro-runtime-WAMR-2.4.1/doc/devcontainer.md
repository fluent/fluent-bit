# Visual Studio Code development container

We all know Docker containers and may use them a lot in school or work. It resolves dependency management for our projects/applications, prevents package version confusion and conflict, and contamination of the local environment. 

Now WAMR has a Dockerfile  under path `.devcontainer` to create a container image, dev container images that you could easily use in VS Code. In case you prefer other IDE like Clion, you can also build it and use for the IDE you like.

## How to use it 

It's straightforward to use Docker in VS Code! First, you have VS Code and Docker installed(if not yet, check [next section](#learn-more-about-docker-and-vs-code) for howto). Then you need to download Docker in VS Code extensions marketplace. 

And that's it, and you are good to go! When you open the root folder of WAMR, in the bottom right corner, the Docker extension will pop a notification and ask if you like to reopen the folder in a container.

If you encounter any problems or get stuck somewhere, may this video [demo](https://youtu.be/Uvf2FVS1F8k) for docker usage in VS Code will help. 

## Learn more about Docker and VS Code

[Install Docker](https://docs.docker.com/get-docker/)

[Install VS Code](https://code.visualstudio.com/)

[Docker extension for VS Code](https://code.visualstudio.com/docs/containers/overview)

[Remote development with Docker in VS Code](https://code.visualstudio.com/docs/remote/containers#_getting-started)

[What is dev container image in VS Code](https://code.visualstudio.com/docs/remote/containers#_prebuilding-dev-container-images)
