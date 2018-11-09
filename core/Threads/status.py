#!/usr/bin/env python

import click
import threading

status_lines = {
    'status_line': '== MALTRAIL =='
}

def show_status():
    threading.Timer(1, show_status, []).start()
    click.clear()
    for _, value in status_lines.iteritems():
        click.echo(value)
