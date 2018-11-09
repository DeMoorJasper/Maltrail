#!/usr/bin/env python

import click
import threading

status_lines = [''] * 10

status_lines[0] = '== MALTRAIL =='
status_lines[3] = '== STATISTICS =='

def set_status(status_message):
    status_lines[1] = click.style('STATUS: ', fg='blue') + click.style(status_message, fg='white')

def show_status():
    threading.Timer(1, show_status, []).start()
    click.clear()
    for value in status_lines:
        click.echo(value)
