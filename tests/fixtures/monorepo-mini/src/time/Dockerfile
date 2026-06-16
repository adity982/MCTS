FROM python:3.12-slim
ENV LOCAL_TIMEZONE=${LOCAL_TIMEZONE:-"UTC"}
ENTRYPOINT ["mcp-server-time", "--local-timezone", "${LOCAL_TIMEZONE}"]
