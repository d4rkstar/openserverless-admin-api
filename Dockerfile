# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
#
FROM python:3.12-slim-bullseye

# Install system dependencies and uv
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpam-modules-bin \
    curl \
    telnet \
    inetutils-ping \
    zip \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Add openserverless user
RUN useradd -m -u 1001 -s /bin/bash openserverless
WORKDIR /home/openserverless


# Copy source code con permessi corretti
ADD --chown=openserverless:openserverless openserverless /home/openserverless/openserverless/
ADD --chown=openserverless:openserverless run.sh pyproject.toml uv.lock /home/openserverless/

# Install uv (Python dependency manager)
RUN pip install --no-cache-dir uv

# Install Python dependencies usando il lockfile
RUN uv venv && uv pip install --requirement pyproject.toml

# ...existing code...
USER openserverless
ENV HOME=/home/openserverless
EXPOSE 5000

CMD ["uv", "run", "-m", "openserverless"]
