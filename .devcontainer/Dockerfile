FROM python:3.12-bullseye
RUN apt-get update && apt-get install -y curl gnupg && rm -rf /var/lib/apt/lists/*
RUN curl -sL https://aka.ms/InstallAzureCLIDeb | bash
RUN pip install jupyterlab
RUN curl -fsSL https://code-server.dev/install.sh | sh
ENV HOME=/home/vscode
ENV USER=vscode
RUN useradd -ms /bin/bash $USER && mkdir -p /home/$USER/.local && chown -R $USER:$USER /home/$USER
USER $USER
EXPOSE 8080 8888
WORKDIR /home/$USER
CMD ["sh", "-c", "code-server --bind-addr 0.0.0.0:8080 & jupyter lab --ip=0.0.0.0 --port=8888 --no-browser --allow-root"]
# docker run -it -p 8080:8080 -p 8888:8888 my-dev-container