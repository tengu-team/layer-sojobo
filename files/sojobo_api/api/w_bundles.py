#!/usr/bin/python3
# Copyright (C) 2017  Qrama
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
# pylint: disable=c0111,c0301,c0325,c0103,r0913,r0902,e0401,C0302,e0611
import asyncio
from importlib import import_module
from random import randint
import os
import re
import base64
import datetime
from subprocess import Popen
import json
import tempfile
import hashlib
import requests
import yaml
from flask import abort, Response
from sojobo_api.api.storage import w_datastore as datastore
from sojobo_api import settings


DEFAULT_LOGO="PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiIHN0YW5kYWxvbmU9Im5vIj8+DQo8c3ZnDQogICB4bWxuczpkYz0iaHR0cDovL3B1cmwub3JnL2RjL2VsZW1lbnRzLzEuMS8iDQogICB4bWxuczpjYz0iaHR0cDovL2NyZWF0aXZlY29tbW9ucy5vcmcvbnMjIg0KICAgeG1sbnM6cmRmPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5LzAyLzIyLXJkZi1zeW50YXgtbnMjIg0KICAgeG1sbnM6c3ZnPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyINCiAgIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyINCiAgIHhtbG5zOnNvZGlwb2RpPSJodHRwOi8vc29kaXBvZGkuc291cmNlZm9yZ2UubmV0L0RURC9zb2RpcG9kaS0wLmR0ZCINCiAgIHhtbG5zOmlua3NjYXBlPSJodHRwOi8vd3d3Lmlua3NjYXBlLm9yZy9uYW1lc3BhY2VzL2lua3NjYXBlIg0KICAgdmVyc2lvbj0iMS4xIg0KICAgaWQ9IkxheWVyXzEiDQogICB4PSIwIg0KICAgeT0iMCINCiAgIHZpZXdCb3g9Ii0xNTUgMzgzLjMgMTAwIDEwMCINCiAgIHhtbDpzcGFjZT0icHJlc2VydmUiDQogICBlbmFibGUtYmFja2dyb3VuZD0ibmV3IC0xNTUgMzgzLjMgNjg3LjUgMjM1LjciDQogICBzb2RpcG9kaTpkb2NuYW1lPSJsb2dvX2RlZmF1bHQuc3ZnIg0KICAgd2lkdGg9IjEwMCINCiAgIGhlaWdodD0iMTAwIg0KICAgaW5rc2NhcGU6dmVyc2lvbj0iMC45Mi4yICg1YzNlODBkLCAyMDE3LTA4LTA2KSI+PG1ldGFkYXRhDQogICAgIGlkPSJtZXRhZGF0YTM1Ij48cmRmOlJERj48Y2M6V29yaw0KICAgICAgICAgcmRmOmFib3V0PSIiPjxkYzpmb3JtYXQ+aW1hZ2Uvc3ZnK3htbDwvZGM6Zm9ybWF0PjxkYzp0eXBlDQogICAgICAgICAgIHJkZjpyZXNvdXJjZT0iaHR0cDovL3B1cmwub3JnL2RjL2RjbWl0eXBlL1N0aWxsSW1hZ2UiIC8+PGRjOnRpdGxlPjwvZGM6dGl0bGU+PC9jYzpXb3JrPjwvcmRmOlJERj48L21ldGFkYXRhPjxkZWZzDQogICAgIGlkPSJkZWZzMzMiIC8+PHNvZGlwb2RpOm5hbWVkdmlldw0KICAgICBwYWdlY29sb3I9IiNmZmZmZmYiDQogICAgIGJvcmRlcmNvbG9yPSIjNjY2NjY2Ig0KICAgICBib3JkZXJvcGFjaXR5PSIxIg0KICAgICBvYmplY3R0b2xlcmFuY2U9IjEwIg0KICAgICBncmlkdG9sZXJhbmNlPSIxMCINCiAgICAgZ3VpZGV0b2xlcmFuY2U9IjEwIg0KICAgICBpbmtzY2FwZTpwYWdlb3BhY2l0eT0iMCINCiAgICAgaW5rc2NhcGU6cGFnZXNoYWRvdz0iMiINCiAgICAgaW5rc2NhcGU6d2luZG93LXdpZHRoPSIzODQwIg0KICAgICBpbmtzY2FwZTp3aW5kb3ctaGVpZ2h0PSIyMDA0Ig0KICAgICBpZD0ibmFtZWR2aWV3MzEiDQogICAgIHNob3dncmlkPSJmYWxzZSINCiAgICAgaW5rc2NhcGU6em9vbT0iMC45NjE0NTQ1NSINCiAgICAgaW5rc2NhcGU6Y3g9IjM0My43NSINCiAgICAgaW5rc2NhcGU6Y3k9IjExNy44NSINCiAgICAgaW5rc2NhcGU6d2luZG93LXg9Ii0xNiINCiAgICAgaW5rc2NhcGU6d2luZG93LXk9Ii0xNiINCiAgICAgaW5rc2NhcGU6d2luZG93LW1heGltaXplZD0iMSINCiAgICAgaW5rc2NhcGU6Y3VycmVudC1sYXllcj0iTGF5ZXJfMSIgLz48Zw0KICAgICB0cmFuc2Zvcm09Im1hdHJpeCgwLjQ4OTc5NTg3LDAsMCwwLjQ4OTc5NTg3LC0xNTMuOTc5NTksLTMzLjE2MzA2NykiDQogICAgIGlkPSJsYXllcjEiDQogICAgIGlua3NjYXBlOmxhYmVsPSJMYXllciAxIj48cGF0aA0KICAgICAgIGlua3NjYXBlOmNvbm5lY3Rvci1jdXJ2YXR1cmU9IjAiDQogICAgICAgaW5rc2NhcGU6ZXhwb3J0LXlkcGk9IjcxLjk4NDIiDQogICAgICAgaW5rc2NhcGU6ZXhwb3J0LXhkcGk9IjcxLjk4NDIiDQogICAgICAgaW5rc2NhcGU6ZXhwb3J0LWZpbGVuYW1lPSJDOlxVc2Vyc1xHcmVnb3J5XERyaXZlXElCQ05cdGVuZ3VfbG9nby0zMi5wbmciDQogICAgICAgaWQ9InBhdGgzODMyLTUiDQogICAgICAgZD0ibSA3Mi45NDQ2MDgsODU0LjM2MjE4IGMgMCwwIDEuNjk3OTgsMy42NDg1MyAyLjYxNzcxLDUuMjUyNjQgMC45MTk3MywxLjYwNDExIDEuNzMzMDksMi43NjUwMyAyLjg1ODgyLDQuMzc0MzMgMS4xMjU3MiwxLjYwOTMxIDIuNDQ3MzEsMy43NTA3OSAzLjkyNjU2LDUuMjUyNjUgMS40NzkyNiwxLjUwMTg2IDMuMTU1ODYsMi43NzQ0MiA0LjgyMjEsMy43MTk5IDEuNjY2MjQsMC45NDU0OSAzLjM1MDg5LDEuMzk1NDMgNS4wMjg3NiwxLjk4MDUxIDEuNjc3ODcsMC41ODUwNyA0LjExNjAzLDEuNTMyNzMgNS4wMjg3NiwxLjUzMjczIDAuOTEyNzgsMCAzLjY5MzQwMiwwLjIzODQ1IDUuNDc2NTIyLDAgMS43ODMxMywtMC4yMzg0NCA0LjI2NDQ1LC0xLjI3NDQxIDUuMTE0ODUsLTEuNTMyNzMgMC44NTA1LC0wLjI1ODMzIDMuMzY1MzIsLTEuMDM0NzEgNS4wMjg3NiwtMS45ODA1MSAxLjY2MzQ4LC0wLjk0NTggMy4zMjU3NiwtMi4yMTg3MSA0LjgwNDksLTMuNzE5OSAxLjQ3OTE0LC0xLjUwMTIgMi44MTg1MywtMy42NDI4NCAzLjk0Mzc2LC01LjI1MjY1IDEuMTI1MjgsLTEuNjA5ODEgMS45MjIxMiwtMi43NzAzOSAyLjg0MTYyLC00LjM3NDMzIDAuOTE5NTEsLTEuNjAzOTMgMi42MzQ5NiwtNS4yNTI2NCAyLjYzNDk2LC01LjI1MjY0IDAsMCAtMy42NjI5OCwyLjEwOTcgLTUuNDc2NTgsMi40MTEwNSAtMS44MTM1NSwwLjMwMTM0IC01LjAyODc2LC0wLjQzMDU1IC01LjAyODc2LC0wLjQzMDU1IDAsMCAtMS4xNTYwOSwzLjg1MDg1IC0yLjQxMTA1LDUuOTA3MDcgLTEuMjU0OSwyLjA1NjIzIC0zLjQzMTEzLDQuNjYwNTcgLTUuMjUyNjEsNi4xMzA5NiAtMS44MjE0OSwxLjQ3MDM5IC0zLjczMjY0LDIuMjk0MDYgLTUuMjUyNjIsMi44NDE1OSAtMS41MjAwNCwwLjU0NzUzIC0yLjQxMDM5LDAuNzIzMzIgLTMuNjUxMDIsMC43MjMzMiAtMS4yNDA2ODIsMCAtMi4xMzA5ODIsLTAuMTc1NzkgLTMuNjUxMDEyLC0wLjcyMzMyIC0xLjUyMDA5LC0wLjU0NzUzIC0zLjQzMzgzLC0xLjM3MDkgLTUuMjUyNjcsLTIuODQxNTkgLTEuODE4ODQsLTEuNDcwNjkgLTMuOTgzMTcsLTQuMDc1MyAtNS4yMzU0MywtNi4xMzA5NiAtMS4yNTIyNSwtMi4wNTU2NSAtMi40MTEwNCwtNS45MDcwNyAtMi40MTEwNCwtNS45MDcwNyAwLDAgLTMuMjE1MTYsMC43MzE5IC01LjAyODc2LDAuNDMwNTUgLTEuODEzNjEsLTAuMzAxMzUgLTUuNDc2NTMsLTIuNDExMDUgLTUuNDc2NTMsLTIuNDExMDUgeiBtIDEuNzIyMTgsMjcuMTI0MyBjIDQuMzkwODEsMi40ODQwNiA2LjM2ODgsNC45NTI1OCA4LjM1MjUzLDguMzUyNTcgMS43NDcwOSwyLjk5NDIyIDIuNDUzOTMsNi41NzI3NyAyLjc4OTk5LDEwLjAyMzA3IDAuMjM0NTQsMi40MDgwNyAwLjM5NDg2LDUuMDA2MjkgLTAuNTUxMSw3LjIzMzE1IC0wLjg3MzY1LDIuMDU2NjEgLTIuNTE1NTQsMy45MTE0NiAtNC40NjA0Nyw1LjAxMTU0IC0wLjEyMywwLjA2OTUgLTAuMjUzMjMsMC4xMjQzMyAtMC4zNzg4OCwwLjE4OTQ0IDAuMDU4OCwwLjUxMTA4IDAuMTAzMzMsMS4wMjM2MyAwLjEwMzMzLDEuNTQ5OTYgMCw4Ljk3ODQ1IC04Ljc1MjAyLDE2LjYxOTUyIC0xOS41NDY3NDQsMTcuMDY2NzggLTEwLjc5NDY2OCwwLjQ0NzI2IC0xOS41NDY2OTQsLTYuNDY5NDggLTE5LjU0NjY5NCwtMTUuNDQ3OTQgMCwtNC41NTA4OSAyLjI0OTYzMywtOC43NDc1MiA1Ljg3MjY1NSwtMTEuODQ4NTggLTIuNjQ5Njc0LC0xLjI3Njc1IC01LjI4Nzk0MSwtMi43NDU5MiAtOC4wOTQyOTIsLTMuMjM3NyAtMy4yOTUwNjMsLTAuNTc3NDIgLTcuNTY3Mjc3LC0wLjk1MTM4IC0xMC44MzI0NzIsLTAuMjIzODggLTIuNjc0MjUzLDAuNTk1ODMgLTUuNDEyNDMzLDIuMjM5NiAtNi41Nzg3MTksNC43MTg3NyAtMS42MTExODgsMy40MjQ3MiAxLjUzOTMyNCw3LjQwMjUgMi4yMjE2MzcsMTEuMTI1MjcgMC40MDY5MywyLjIyMDUgMS4xMzU5NzYsNC40MjQ2MyAxLjExOTM4OCw2LjY4MjA1IC0wLjAxMzIzLDEuODM0OTIgLTEuNzk1NDE5LDMuODc5NjQgLTEuMzk0OTM3LDUuNTEwOTcgLTEuNjY3Nzg0LC0wLjQwMjU5IC0zLjk0NDMxMSwtMC43MTc5OCAtNS4xNDkzMzksMC4xNTQ5OSAtMi4wMzY2ODksMS40NzU0MSAtMi42Njk0MDQsNC4yMTkzNCAtMi42Njk0MDQsNC4yMTkzNCAwLDAgMS43NDgyNDUsLTIuMTg3NTIgMy43MzcxNTQsLTMuMDY1NDggMS4xNDQ1MTgsLTAuNTA1MjEgMi45NzgwNzMsLTAuNjYwNTEgNC4zMzk4ODgsLTAuNzA2MDkgMC4wMDU1LDAuMDA3IDAuMDEyNzksMC4wMTA2IDAuMDE3MjUsMC4wMTcyIDAuMjcwMDM3LDAuMzk0MzkgMC41ODQ4MjQsMC43MzYzNSAwLjkyOTkyMSwxLjAzMzMgLTEuNjA2ODM0LDAuMTI3NzcgLTQuNzUwMDcsMC41MDkyMiAtNi4yMzQyMjksMS41ODQ0MSAtMi4wMzY2ODksMS40NzU0IC0zLjk0MzgxNiw2LjU3ODcyIC0zLjk0MzgxNiw2LjU3ODcyIDAsMCAyLjQxNjY3MSwtMi44NTQ2OSA0LjI3MTAwMiwtNC4yNzEwMSAxLjQ4NjQ3NCwtMS4xMzUzNyA0LjkwNTE0OCwtMi45MjY5IDYuMjUxNDc4LC0zLjYxNjU3IDMuMjg2ODUzLDIuMzk3OSA5LjE4MzUzNSwxLjM4NzM0IDEzLjM2NDEwMSwyLjI5MDUgNC42NjMzMjgsMS4wMDc0MyA5LjY2NjY4MiwxLjgxNTUgMTQuODk2ODY3LDIuMTg3MTYgNS4yMzAxMzIsMC4zNzE2NiAxMC43NDI5MTUsMy4wNDQyNCAxNi42NzA2ODUsMy4xMTcxNSA1LjkyNzcxLDAuMDcyOSA5LjE4MTA1LC0wLjgxMzQ0IDEyLjc5NTc1LC0zLjM0MTAzIDIuNDA0NTUsLTEuNjgxMzMgMy42NTEwOCwtNC42MzM2MSA1LjAxMTU3LC03LjIzMzE1IDEuNDcwMzMsLTIuODA5NDIgMC40MTQ1MywtNS4zOTk4NCAzLjE4NiwtNi45NDAzNyAyLjkzMDI0LC0xLjI3MzMgNi4xNjc3NywtMC40NTk0OSA4Ljc4MzE2MiwtMC4yOTI3NyAzLjMxMjIxLDAuMjE5NTkgNi4zMDkxOCwtMC45ODU3IDguNzgzMDYsMC4yOTI3NyAyLjc3MTU3LDEuNTQwNTMgMS43MTU2Nyw0LjEzMDk1IDMuMTg2MDUsNi45NDAzNyAxLjM2MDQ0LDIuNTk5NTQgMi42MDcwOCw1LjU1MTgyIDUuMDExNTEsNy4yMzMxNSAzLjYxNDc2LDIuNTI3NTkgNi44NjgwNSwzLjQxMzkzIDEyLjc5NTgxLDMuMzQxMDMgNS45Mjc3MSwtMC4wNzI5IDExLjQ0MDUsLTIuNzQ1NDkgMTYuNjcwNjksLTMuMTE3MTUgNS4yMzAxMywtMC4zNzE2NiAxMC4yMzM1OSwtMS4xNzk3MyAxNC44OTY4MSwtMi4xODcxNiA0LjE4MDYyLC0wLjkwMzE2IDEwLjA3NzMsMC4xMDc0IDEzLjM2NDEsLTIuMjkwNSAxLjM0NjM4LDAuNjg5NjcgNC43NjUsMi40ODEyIDYuMjUxNTMsMy42MTY1NyAxLjg1NDI4LDEuNDE2MzIgNC4yNzEsNC4yNzEwMSA0LjI3MSw0LjI3MTAxIDAsMCAtMS45MDcxMiwtNS4xMDMzMiAtMy45NDM3NiwtNi41Nzg3MiAtMS40ODQyMSwtMS4wNzUxOSAtNC42Mjc0NSwtMS40NTY2NCAtNi4yMzQzNCwtMS41ODQ0MSAwLjM0NTI3LC0wLjI5Njk1IDAuNjU5OTQsLTAuNjM4OTEgMC45MzAwNCwtMS4wMzMzIDAuMDA2LC0wLjAwNyAwLjAxMjgsLTAuMDEwNiAwLjAxNzIsLTAuMDE3MiAxLjM2MTc2LDAuMDQ1NiAzLjE5NTM3LDAuMjAwODggNC4zMzk4OSwwLjcwNjA5IDEuOTg4ODUsMC44Nzc5NiAzLjczNzEsMy4wNjU0OCAzLjczNzEsMy4wNjU0OCAwLDAgLTAuNjMyNzIsLTIuNzQzOTMgLTIuNjY5MzUsLTQuMjE5MzQgLTEuMjA1MDksLTAuODcyOTcgLTMuNDgxNTYsLTAuNTU3NTggLTUuMTQ5MjksLTAuMTU0OTkgMC40MDA0MywtMS42MzEzMyAtMS4zODE0OSwtMy42NzYwNSAtMS4zOTQ5OSwtNS41MTA5NyAtMC4wMTY1LC0yLjI1NzQyIDAuNzEyNDYsLTQuNDYxNTUgMS4xMTk0NSwtNi42ODIwNSAwLjY4MjMxLC0zLjcyMjc3IDMuODMyNzEsLTcuNzAwNTUgMi4yMjE1OCwtMTEuMTI1MjcgLTEuMTY2MzQsLTIuNDc5MTcgLTMuOTA0NTIsLTQuMTIyOTQgLTYuNTc4NzIsLTQuNzE4NzcgLTMuMjY1MjUsLTAuNzI3NSAtNy41Mzc0MSwtMC4zNTM1NCAtMTAuODMyNTMsMC4yMjM4OCAtMi44MDYzLDAuNDkxNzggLTUuNDQ0NTYsMS45NjA5NSAtOC4wOTQxOCwzLjIzNzcgMy42MjMwMiwzLjEwMTA2IDUuODcyNiw3LjI5NzY5IDUuODcyNiwxMS44NDg1OCAwLDguOTc4NDYgLTguNzUyMDMsMTUuODk1MiAtMTkuNTQ2NzUsMTUuNDQ3OTQgLTEwLjc5NDY3LC0wLjQ0NzI2IC0xOS41NDY2OSwtOC4wODgzMyAtMTkuNTQ2NjksLTE3LjA2Njc4IDAsLTAuNTI2MzMgMC4wNDQ2LC0xLjAzODg4IDAuMTAzMzMsLTEuNTQ5OTYgLTAuMTI1NzEsLTAuMDY1MSAtMC4yNTU5MywtMC4xMTk5IC0wLjM3ODg4LC0wLjE4OTQ0IC0xLjk0NDkzLC0xLjEwMDA4IC0zLjU4Njc2LC0yLjk1NDkzIC00LjQ2MDQxLC01LjAxMTU0IC0wLjk0NTk2LC0yLjIyNjg2IC0wLjc4NTcsLTQuODI1MDggLTAuNTUxMSwtNy4yMzMxNSAwLjMzNiwtMy40NTAzIDEuMDQyODQsLTcuMDI4ODUgMi43ODk4NywtMTAuMDIzMDcgMS45ODM3OSwtMy4zOTk5OSAzLjk2MTczLC01Ljg2ODUxIDguMzUyNTksLTguMzUyNTcgLTQuMjk5MTYsMC40NTcgLTYuNTQzNjEsMS42OTY4MyAtOC4zNTI1OSwyLjc3MjcxIC0yLjE0NTY0LDEuMjc2MTcgLTMuNjMzNTQsMi4zNzg2OSAtNS4wMTE1MSw0LjQ2MDQ0IC0xLjY5NTQ1LDIuNTYxMzMgLTEuNTgwMSw2LjM1MDExIC0zLjkwOTMxLDguMzUyNTYgLTIuNTY5NDksMS42NTA1IC01Ljc0MDM0LDAuODM4MjYgLTguMDU5OCwwLjQ2NDk5IC0zLjI4OTU1MiwwLjA4NSAtNi4wNDU1OTIsMS4xNDk3NyAtOC4wNTk3OTIsLTAuNDY0OTkgLTIuMzI5MjEsLTIuMDAyNDUgLTIuMjEzOTgsLTUuNzkxMjMgLTMuOTA5MzcsLTguMzUyNTYgLTEuMzc4MDIsLTIuMDgxNzUgLTIuODY1ODIsLTMuMTg0MjcgLTUuMDExNTcsLTQuNDYwNDQgLTEuODA4OTIsLTEuMDc1ODggLTQuMDUzNDIsLTIuMzE1NzEgLTguMzUyNTMsLTIuNzcyNzEgeiBtIC0xOC4yODk1MzMsMjUuOTg3NjcgYyAtMS40MjQ4NjEsMS40OTc4IC0yLjMwNzcxOCwzLjUyMTYxIC0yLjMwNzcxOCw1Ljc1MjA3IDAsNC42MTE3OSAzLjc0MDc5MSw4LjMzNTM0IDguMzUyNTMxLDguMzM1MzQgNC40ODIzNSwwIDguMTMzNjQsLTMuNTIzOTQgOC4zMzUzNSwtNy45NTY0NiAtMy4xMTAzNCwtMC42MjcxMyAtNS45MjM1OCwtMi41MDkyOSAtOC44ODY0NCwtMy43MTk5IC0xLjg1MDQyLC0wLjc1NjEgLTMuNjcwNzQ4LC0xLjU4NzY0IC01LjQ5MzcyMywtMi40MTEwNSB6IG0gODcuMjQ1NTM1LDAgYyAtMS44MjMwMywwLjgyMzQxIC0zLjY0MzMsMS42NTQ5NSAtNS40OTM3NywyLjQxMTA1IC0yLjk2MjgxLDEuMjEwNjEgLTUuNzc2MDUsMy4wOTI3NyAtOC44ODY0NCwzLjcxOTkgMC4yMDE3Niw0LjQzMjUyIDMuODUzMDUsNy45NTY0NiA4LjMzNTM0LDcuOTU2NDYgNC42MTE4NiwwIDguMzUyNTksLTMuNzIzNTUgOC4zNTI1OSwtOC4zMzUzNCAwLC0yLjIzMDQ2IC0wLjg4MjkxLC00LjI1NDI3IC0yLjMwNzcyLC01Ljc1MjA3IHogTSA1Ny40MTA1NjIsOTM4Ljk5IGMgLTIuNjY0OTM5LDAuMDA4IC01LjMzNzI2NCwwLjgzMDcgLTcuNTQzMTM5LDIuNTQ4ODMgLTYuMjU1MTE2LDMuODgwMyAtOS41Njc1OTUsMTEuODU1ODMgLTcuMTEyNTY4LDE4LjkyNjczIDEuMjI0OTc4LDQuOTM4MzkgLTYuODk2NzU4LDYuNjg4NTkgLTEwLjg2Njk3MSw3LjgwMTQ3IC01LjY5NzczNiwxLjYzOTcyIC0xMi4zNDc4MjMsMi41NzUyIC0xNi44MjU2NTEsLTIuMzU5MzggLTEuOTI2NjksLTEuMDEzODIgLTMuMTI0NjY0LC03LjEwODY2IC0yLjMwNzc3MywtMi4xNTI3MyAwLjE1MDI4NCw1LjE2ODcxIDMuMDgwMzAxLDEwLjQ3OTY2IDguNjI4MTM5LDExLjIyODYgNi41NzYxODUsLTEuNzIzMzYgMS4yNDk3NzcsNi41MzM3OCAzLjUzMDQ5MiwxMC4yNDY5NiAyLjg4ODg1LDguMjI5MzcgOC43OTIwMzYsMTYuMTk5MDIgMTcuNDYyODMsMTguODIzNDIgNC45NDY5MjIsMi4zMDI2IDEyLjI4NzM2OCwwLjY0OTggMTQuMzI4NTIxLDcuMTgxNSAzLjgxMDI4NSw3LjM4NTMgNS4zMTc0NzYsMTUuNjMzIDUuODM4MjA2LDIzLjg1MjEgMS4xMjYwMSw1LjIxOTkgMi4zNzU3MywxMS4yOTk1IDYuODAyNjQsMTQuNzI0NyA1Ljg2MDY5LDEuNjk3MyAxMS45NTcxNSwtMS4wMzI3IDE3Ljg1ODk1LC0xLjQ5ODMgNC4yNzQ2NCwtMC41MTk3IDguNTA5MDUsLTEuNTUzNiAxMi43OTU4MTIsLTEuODYgNC4yODY3NywwLjMwNjQgOC41MjEwNiwxLjM0MDMgMTIuNzk1NzYsMS44NiA1LjkwMTc1LDAuNDY1NiAxMS45OTgzMiwzLjE5NTYgMTcuODU5MDEsMS40OTgzIDQuNDI2ODUsLTMuNDI1MiA1LjY3NjUyLC05LjUwNDggNi44MDI1OCwtMTQuNzI0NyAwLjUyMDY3LC04LjIxOTEgMi4wMjc5MiwtMTYuNDY2OCA1LjgzODE1LC0yMy44NTIxIDIuMDQxMjEsLTYuNTMxNyA5LjM4MTY2LC00Ljg3ODkgMTQuMzI4NTIsLTcuMTgxNSA4LjY3MDg1LC0yLjYyNDQgMTQuNTc0MDksLTEwLjU5NDA1IDE3LjQ2Mjk0LC0xOC44MjM0MiAyLjI4MDcyLC0zLjcxMzE4IC0zLjA0NTgsLTExLjk3MDMyIDMuNTMwNDQsLTEwLjI0Njk2IDUuNTQ3NzgsLTAuNzQ4OTQgOC40Nzc4NSwtNi4wNTk4OSA4LjYyODA4LC0xMS4yMjg2IDAuODE2OSwtNC45NTU5MyAtMC4zODEwMiwxLjEzODkxIC0yLjMwNzY2LDIuMTUyNzMgLTQuNDc3ODMsNC45MzQ1OCAtMTEuMTI4MDIsMy45OTkxIC0xNi44MjU3MSwyLjM1OTM4IC0zLjk3MDI2LC0xLjExMjg4IC0xMi4wOTE5NCwtMi44NjMwOCAtMTAuODY2OTEsLTcuODAxNDcgMi40NTQ5NywtNy4wNzA5IC0wLjg1NzU2LC0xNS4wNDY0MyAtNy4xMTI2MiwtMTguOTI2NzMgLTIuMjA1OTMsLTEuNzE4MTMgLTQuODc4MjYsLTIuNTQxMDMgLTcuNTQzMTQsLTIuNTQ4ODMgLTMuNDI2MzQsLTAuMDEgLTYuODQzMDgsMS4zNDM3NyAtOS4yOTk3NiwzLjk0Mzc5IDAuODY1ODgsMC4yNTE2NiAxLjcxNTE3LDAuNTI4MzUgMi41NjYwMSwwLjgyNjY1IDkuNTAwMjUsMi4zNTU1OCAxMy40MTYzNSwxNC42MzUzNSA4LjQ5MDM3LDIyLjY0NjY0IC0yLjM0MTcyLDQuMDU1MjggLTkuMTg3MzQsOC4wMTQwNSAtMTIuNzYxMzcsMy42MTY1NyAtNS4zNjYxOSwtNS4yMzIyOCAtOS45NzEzMyw0LjY1NTMxIC0xNC44NjIzNyw2LjUyNzA2IC01LjY2OTA4LDMuMTg5MTcgLTEwLjkxNjQ2LDUuMDg5NzggLTE2LjcyMjMyLDQuODU2NTQgLTUuODA1OTEyLC0wLjIzMzI1IC0xMi4zOTM4NDIsLTEuNzkzMzUgLTE2LjcyMjM3MiwtNC44NTY1NCAtNC44OTExLC0xLjg3MTc1IC05LjQ5NjE3LC0xMS43NTkzNCAtMTQuODYyNDMsLTYuNTI3MDYgLTMuNTczOTcsNC4zOTc0OCAtMTAuNDE5NjQxLDAuNDM4NzEgLTEyLjc2MTMwNywtMy42MTY1NyAtNC45MjYwMzYsLTguMDExMjkgLTEuMDA5ODMxLC0yMC4yOTEwNiA4LjQ5MDMwNywtMjIuNjQ2NjQgMC44NTEwMSwtMC4yOTgzIDEuNzAwMTksLTAuNTc0OTkgMi41NjYwOCwtMC44MjY2NSAtMi40NTY3NCwtMi42MDAwMiAtNS44NzM0ODUsLTMuOTUzODIgLTkuMjk5NzY2LC0zLjk0Mzc5IHogbSAtNS4xODM3ODMsMzQuNTgxMzQgYyAyLjIwNTc2NSwtMC4wMjM0IDQuNDM4MDk0LDAuNTUyOTkgNi4zMzc2MTYsMS43NTY2MiA0LjE0MTQzMywyLjUyOTE0IDguODQyNDYzLDYuODQ5MDkgMTMuOTMyNDQzLDMuNzE5OSA1LjY3NDIxLC0xLjg5MDgzIDExLjA3NDE5LDIuMjQ0OTEgMTUuOTMwMTgsNC42NjcxMSAzLjc5NDk2LDIuMDM1NjQgNy42OTA1LDMuMTAxMTkgMTEuNTczMDMyLDIuOTc5MzYgMy44ODI0OCwtMC4xMjE4MiA4LjYxMDg5LC0xLjE2ODY5IDExLjU3MzA0LC0yLjk3OTM2IDQuODU1OTksLTIuNDIyMiAxMC4yNTU4NiwtNi41NTc5NCAxNS45MzAxMiwtNC42NjcxMSA1LjA4OTkzLDMuMTI5MTkgOS43OTEwMSwtMS4xOTA3NiAxMy45MzIzOSwtMy43MTk5IDUuMDY1NTcsLTMuMjA5NjcgMTIuNDU5NTksLTIuMDA1NzggMTUuNTY4NDksMy4zNDEwMyAxLjg3NDU2LDQuODQ2ODkgLTEuMzgyNDMsMTEuMDM3MTggLTQuMjAyMTIsMTUuMTU1MTYgLTUuMjc1MzIsNy40MDg4NSAtMTAuNTk0ODksMTUuMDM4MzUgLTEzLjc5NDYxLDIzLjYyODI1IC0xLjYzNDI4LDUuNDYwMiAtMy4zNzcyNCwxMS4wNDI2IC0zLjc3MTYsMTYuNzM5NiAxLjQ4NzMsNC45MjIyIC0yLjk0NDEzLDkuMzE1IC03LjUwODcsMTAuMTQzNiAtMTAuMTI3MDEsMC4zNDM5IC0xOC4yMzkxLC01Ljk1MDggLTI3LjcyNzAxLC02LjExMzcgLTkuNDg3OTYyLC0wLjE2MjkgLTE4LjY4NzQyMiw2LjUxMTIgLTI3LjcyNzEyMiw2LjExMzcgLTQuNTY0NTEsLTAuODI4NiAtOC45OTU5NCwtNS4yMjE0IC03LjUwODY5LC0xMC4xNDM2IC0wLjM5NDMxLC01LjY5NyAtMi4xMzczMiwtMTEuMjc5NCAtMy43NzE1NDUsLTE2LjczOTYgLTMuMTk5NzgsLTguNTg5OSAtOC41MTkyOTgsLTE2LjIxOTQgLTEzLjc5NDY3NCwtMjMuNjI4MjUgLTIuODE5NjMyLC00LjExNzk4IC02LjA3NjYxNSwtMTAuMzA4MjcgLTQuMjAyMTE0LC0xNS4xNTUxNiAxLjk0MzE2OCwtMy4zNDE3NiA1LjU1NDc4MiwtNS4wNTg2MyA5LjIzMDg3NCwtNS4wOTc2NSB6IG0gLTAuMTcyMTYzLDIuMzQyMTYgYyAtMS4wMjY2OTQsMC4wMjQgLTEuOTM2NTU1LDAuMjQ2MiAtMi43MDM4NDcsMC42MTk5OCAtMS41MzQ2NCwwLjc0NzU3IC0yLjc5OTM1MiwxLjg4NDczIC0zLjI4OTMzMiwzLjUzMDQ3IC0wLjQ5MDAzNiwxLjY0NTc0IDAuMDA3NywzLjAzMzM0IDAuOTQ3MTcsNS40MDc2NCAwLjkzOTQ1NSwyLjM3NDI5IDMuNTQ5NTYsNS4zNTc1MSA1LjM5MDQ0NSw4LjIxNDc5IDEuODQwODg0LDIuODU3MjcgMy45NTg1ODQsNS43ODMwNyA1LjY0ODc0NSw4LjkyMDkyIDEuNjkwMTA0LDMuMTM3OCAyLjkyOTY4Niw2LjczNjUgNC40NjA0MTEsOS44NjggMS41MzA3MywzLjEzMTYgMy4zODg0OCw1LjUwMjMgNC42ODQzMyw4LjkyMDkgMS4yOTU3OSwzLjQxODYgMS44ODQ4LDYuODIzNyAyLjgyNDM3LDExLjUyMTQgMC43MDQ2MywtNy43NTExIDEuMDczMTUsLTExLjUzNjMgMy4yNzIxNCwtMTIuOTE2MyAxLjg3NjA0LC0xLjE3NzQgMS44OTYxNSwtMC44MzYzIDIuNTgzMjYsMCAwLjkwNjk0LDEuMTAzOCAxLjMxNTY5LDMuNDAyNSAyLjEzNTUsNS42MzE1IDAuODE5NzYsMi4yMjg5IDIuMTE4MjUsNy45NzM3IDIuMTE4MjUsNy45NzM3IDAsMCA4LjkwNDU3LC0yLjQ1MDUgMTIuOTE2MzksLTMuMDQ4MyAxLjk5OTExLC0wLjI5NzkgNC43MDM2MiwtMC41NjgzIDYuOTU3NjAyLC0wLjU2ODMgMi4yNTM5MywwIDQuOTU4NDQsMC4yNzA0IDYuOTU3NiwwLjU2ODMgNC4wMTE3NywwLjU5NzggMTIuOTE2MjgsMy4wNDgzIDEyLjkxNjI4LDMuMDQ4MyAwLDAgMS4yOTg1LC01Ljc0NDggMi4xMTgzMSwtNy45NzM3IDAuODE5NzUsLTIuMjI5IDEuMjI4NSwtNC41Mjc3IDIuMTM1NSwtNS42MzE1IDAuNjg3MDUsLTAuODM2MyAwLjcwNzE3LC0xLjE3NzQgMi41ODMyNywwIDIuMTk4OTMsMS4zOCAyLjU2NzQ1LDUuMTY1MiAzLjI3MjEzLDEyLjkxNjMgMC45Mzk1MSwtNC42OTc3IDEuNTI4NTMsLTguMTAyOCAyLjgyNDM4LC0xMS41MjE0IDEuMjk1NzksLTMuNDE4NiAzLjE1MzU5LC01Ljc4OTMgNC42ODQzMiwtOC45MjA5IDEuNTMwNzMsLTMuMTMxNSAyLjc3MDM2LC02LjczMDIgNC40NjA0NywtOS44NjggMS42OTAxLC0zLjEzNzg1IDMuODA3OCwtNi4wNjM2NSA1LjY0ODc0LC04LjkyMDkyIDEuODQwODksLTIuODU3MjggNC40NTA4OCwtNS44NDA1IDUuMzkwMzksLTguMjE0NzkgMC45Mzk0NiwtMi4zNzQzIDEuNDM3MjEsLTMuNzYxOSAwLjk0NzIzLC01LjQwNzY0IC0wLjQ5MDA0LC0xLjY0NTc0IC0xLjc1NDgxLC0yLjc4MjkgLTMuMjg5MzksLTMuNTMwNDcgLTAuNzY3MzUsLTAuMzczNzggLTEuNjc3MTUsLTAuNTk1OTggLTIuNzAzNzksLTAuNjE5OTggLTEuMDI2NywtMC4wMjQgLTIuMTc2ODQsMC4xNTAyMiAtMy40MDk5NywwLjYxOTk4IC0yLjQ2NjI3LDAuOTM5NTQgLTMuOTE1NDksMi41Nzg2MSAtNS44NzI2LDQuMjM2NTYgLTEuOTU3MTYsMS42NTc5NiAtNS4xNjY1Myw1LjE2NjU0IC01LjE2NjUzLDUuMTY2NTQgbCAzLjUzMDQzLDE0LjU1MjQyIGMgMCwwIC0xLjI0MDAyLDAuMDkxIC0yLjM0MjE2LDAgLTEuMTAyMDgsLTAuMDkxIC0yLjc2NDYzLC0wLjA0NCAtNC4yMzY1LC0wLjY4ODg5IC0xLjQ3MTkzLC0wLjY0NTE1IC0yLjgwNjA4LC0yLjA3NzE5IC00LjIxOTM2LC0zLjI4OTM2IC0xLjQxMzM1LC0xLjIxMjE3IC0zLjUzMDUsLTMuOTk1NDUgLTMuNTMwNSwtMy45OTU0NSAwLDAgLTQuNzMzODYsMS44ODQgLTcuMjg0NzgsMi41ODMyNiAtMi41NTA5NywwLjY5OTI2IC02LjAxMzM1LDEuMTEwNjggLTguNjc5NzgsMS40MTIxOSAtMi40MzQ4LDAuMjc1MyAtNC44NjI5MywwLjQzMzc2IC02LjczMzY5LDAuNDY0OTkgLTEuODcwODEyLC0wLjAzMTIgLTQuMjk4OTkyLC0wLjE4OTY5IC02LjczMzc0MiwtMC40NjQ5OSAtMi42NjY0OCwtMC4zMDE1MSAtNi4xMjg4NiwtMC43MTI5MyAtOC42Nzk3OCwtMS40MTIxOSAtMi41NTA5NywtMC42OTkyNiAtNy4yODQ4NCwtMi41ODMyNiAtNy4yODQ4NCwtMi41ODMyNiAwLDAgLTIuMTE3MTUsMi43ODMyOCAtMy41MzA0MywzLjk5NTQ1IC0xLjQxMzM1LDEuMjEyMTcgLTIuNzQ3NDQsMi42NDQyMSAtNC4yMTkzMSwzLjI4OTM2IC0xLjQ3MTkzLDAuNjQ1MTkgLTMuMTM0NDgsMC41OTc2OSAtNC4yMzY2MiwwLjY4ODg5IC0xLjEwMjA4LDAuMDkxIC0yLjM0MjE2LDAgLTIuMzQyMTYsMCBsIDMuNTMwNDksLTE0LjU1MjQyIGMgMCwwIC0zLjIwOTQyLC0zLjUwODU4IC01LjE2NjUyOSwtNS4xNjY1NCAtMS45NTcxNjYsLTEuNjU3OTUgLTMuNDA2MzMxLC0zLjI5NzAyIC01Ljg3MjY1NiwtNC4yMzY1NiAtMS4yMzMwNzksLTAuNDY5NzYgLTIuMzgzMjE4LC0wLjY0Mzk1IC0zLjQwOTg1NywtMC42MTk5OCB6IG0gNDcuOTQ1NDM0LDQxLjY5MzkgYyAwLjgxNTQ2LDAgMi42MzQzNiwwLjI5ODYgMy4xMzQzMSwwLjUxNjcgMS45NTY0LDAuODUzNCAyLjQyNjA0LDAuNTQ1IDQuMzA1NSwyLjAzMjEgMS44Nzk0MSwxLjQ4NzIgMy43MjM3NiwyLjI5ODEgNS44NTU0MSwzLjU5OTQgMi4xMzE1OCwxLjMwMTMgNi44MTk4MiwzLjA0ODMgNi44MTk4MiwzLjA0ODMgMCwwIC0yLjA4MzI1LDEuNjQ5NyAtMy45OTU0NSwxLjYzNiAtMS45MTIyNSwtMC4wMTQgLTQuNzU5NzcsLTEuNTM5NSAtNi41Nzg3OCwtMi44MDcxIC0xLjgxODk1LC0xLjI2NzcgLTIuNjAyNSwtMi4wNTE5IC00LjIxOTMsLTMuMzU4MyAtMS42Mjg3NywtMS4yNzg1IC0zLjc0NDI3LC0wLjkzOTkgLTUuMzIxNTEsLTEuMDUwNSAtMS41NzcyOTIsLTAuMTEwNiAtNC4wMDAwODIsLTAuMDEgLTUuMzIxNTUyLDEuMDUwNSAtMS42MTY4NywxLjMwNjQgLTIuNDAwMzYsMi4wOTA2IC00LjIxOTM3LDMuMzU4MyAtMS44MTg5NSwxLjI2NzYgLTQuNjY2NDcsMi43OTM1IC02LjU3ODY2LDIuODA3MSAtMS45MTIyNSwwLjAxNCAtMy45OTU0NiwtMS42MzYgLTMuOTk1NDYsLTEuNjM2IDAsMCA0LjY4ODE5LC0xLjc0NyA2LjgxOTgzLC0zLjA0ODMgMi4xMzE1OSwtMS4zMDEzIDMuOTc1OTQsLTIuMTEyMiA1Ljg1NTQsLTMuNTk5NCAxLjg3OTQxLC0xLjQ4NzEgMi4zNDkwNiwtMS4xNzg3IDQuMzA1MzksLTIuMDMyMSAwLjUwMDAxLC0wLjIxODEgMi4zMTg5MSwtMC41MTY3IDMuMTM0NDIyLC0wLjUxNjcgeiINCiAgICAgICBzdHlsZT0iZmlsbDojMDAwMDAwO3N0cm9rZTpub25lO3N0cm9rZS13aWR0aDoxcHg7c3Ryb2tlLWxpbmVjYXA6YnV0dDtzdHJva2UtbGluZWpvaW46bWl0ZXI7c3Ryb2tlLW9wYWNpdHk6MSIgLz48L2c+PC9zdmc+"


###############################################################################
# BUNDLE FUNCTIONS
###############################################################################
def get_all_bundles(company=None):
    """Returns all the bundle types a particular logged in user can see. When
     company is provided, the result also contain company specific bundles."""
    #TODO company specific bundles not yet supported.
    return datastore.get_all_bundle_types()

def determine_closest_type(applications):
    """Given the provided applications (in the same format as the Tengu API
     returns), determines the type of the bundle that fits best. All relevant
     information of the bundle type is returned."""
    for t in datastore.get_all_bundle_types():
        t_application_names = t['bundle']['applications'].keys()
        counter = 0
        for app in applications:
            if app['name'] in t_application_names:
                counter = counter + 1
        if counter == len(t_application_names):
            return t
    return None

def upload_types(repositories, company=None):
    """When no company is provided, all the default bundle types are renewed.
     When this function is executed for a specific company, only the company
     bundle types are renewed. In this context, renewed means drop everything
     from the current DS and add the elements again. All the added bundle types
     are returned."""
    types = []
    errors = []
    datastore.clear_bundle_types()
    for repo in repositories:
        url = 'https://raw.githubusercontent.com/{}/master/'.format(repo)
        res = requests.get(url + 'info.json')
        if res.status_code == 200:
            info = res.json()
            if 'name' in info and 'summary' in info and 'tags' in info:
                res = requests.get(url + 'bundle.yaml')
                if res.status_code == 200:
                    try:
                        bundle = yaml.load(res.text)
                        res = requests.get(url + 'description.md')
                        if res.status_code == 200:
                            description = res.text
                            res = requests.get(url + 'logo.svg')
                            if res.status_code == 200:
                                logo = base64.b64encode(res.text.encode()).decode()
                            else:
                                logo = DEFAULT_LOGO
                            #everything downloaded
                            types.append(type_dict(info['name'], info['summary'], description, logo, bundle, info['tags']))
                        else:
                            errors.append('Could not find description.md from GitHub repository {}'.format(repo))
                    except yaml.YAMLError:
                        errors.append('The bundle.yaml file of repository {} could not be parsed'.format(repo))
                else:
                    errors.append('Could not find bundle.yaml from GitHub repository {}'.format(repo))
            else:
                errors.append('The info.json file of repository {} does not contain the necessary properties'.format(repo))
        else:
            errors.append('Could not find info.json from GitHub repository {}'.format(repo))

    for t in types:
        datastore.create_bundle_type(t['name'], t['summary'], t['description'], t['logo'], t['bundle'], t['tags'])
    for e in errors:
        types.append(e)
    return types

###############################################################################
# HELPER FUNCTIONS
###############################################################################
def type_dict(name, summary, description, logo, bundle, tags=['default']):
    t = {}
    t['name'] = name
    t['summary'] = summary
    t['tags'] = tags
    t['description'] = description
    t['logo'] = logo
    t['bundle'] = bundle
    return t