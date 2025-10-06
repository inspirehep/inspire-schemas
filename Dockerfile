FROM python:3.11-bullseye AS inspire-schemas-py3-tests

ARG APP_HOME=/code
WORKDIR ${APP_HOME}

COPY . .

RUN python -m pip install --user --upgrade pip
RUN python -m pip --no-cache-dir install --user -e .[tests,docs]

ENV PATH="/root/.local/bin:${PATH}"


CMD ["/bin/bash"]
