FROM python:3.11-bullseye AS inspire-schemas-py3-tests

ARG APP_HOME=/code
WORKDIR ${APP_HOME}

COPY . .

RUN python -m pip install --user --upgrade pip "poetry==2.2.1"

ENV PATH="/root/.local/bin:${PATH}"

RUN poetry config virtualenvs.create false \
    && poetry install --with test,docs --no-interaction

RUN poetry run python -m scripts.generate_schemas


CMD ["/bin/bash"]
