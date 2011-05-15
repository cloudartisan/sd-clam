#!/usr/bin/env python


import os
import re
import time
import socket


TIMEOUT = 3
CLAMD_SOCKET = "/var/run/clamav/clamd.ctl"

THREADS_RE = re.compile(
        'THREADS: '            \
        'live (?P<live>\d+) +' \
        'idle (?P<idle>\d+) +' \
        'max (?P<max>\d+) +'   \
        'idle-timeout (?P<idle_timeout>\d+)')

MEMSTATS_RE = re.compile(
        'MEMSTATS: '                              \
        'heap (?P<heap>\d+\.?\d*)M +'             \
        'mmap (?P<mmap>\d+\.?\d*)M +'             \
        'used (?P<used>\d+\.?\d*)M +'             \
        'free (?P<free>\d+\.?\d*)M +'             \
        'releasable (?P<releasable>\d+\.?\d*)M +' \
        'pools (?P<pools>\d+) +'                  \
        'pools_used (?P<pools_used>\d+\.?\d*)M +'  \
        'pools_total (?P<pools_total>\d+\.?\d*)M')


class Clam:
    """
    Collects and returns stats from Clam anti-virus.
    """
    def __init__(self, agent_config, checks_logger, raw_config):
        self.agent_config = agent_config
        self.checks_logger = checks_logger
        self.raw_config = raw_config

    def parse_threads_line(self, line):
        """
        Recommended group:

        Title: Threads
        Key: live
        Key: idle
        Key: max
        Key: idle_timeout
        """
        stats = {}
        m = THREADS_RE.search(line)
        if not m:
            return stats
        try:
            stats['live'] = int(m.group('live'))
            stats['idle'] = int(m.group('idle'))
            stats['max'] = int(m.group('max'))
            stats['idle_timeout'] = int(m.group('idle_timeout'))
        except (ValueError, IndexError):
            self.checks_logger.error('Failed to parse THREADS line')
        return stats

    def parse_pools_line(self, line):
        """
        Recommended group:

        Title: Pools
        Key: pools
        """
        stats = {}
        try:
            stats['pools'] = int(line.split()[1])
        except (IndexError, ValueError):
            self.checks_logger.error('Failed to parse POOLS line')
        return stats

    def parse_queue_line(self, line):
        """
        Recommended group:

        Title: Queue
        Key: queue
        """
        stats = {}
        try:
            stats['queue'] = int(line.split()[1])
        except (IndexError, ValueError):
            self.checks_logger.error('Failed to parse QUEUE line')
        return stats

    def parse_memstats_line(self, line):
        """
        Recommended groups:

        Title: Memory
        Key: heap
        Key: mmap
        Key: used
        Key: free
        Key: releasable

        Title: Pools
        Key: pools
        Key: pools_used
        Key: pools_total
        """
        stats = {}
        m = MEMSTATS_RE.search(line)
        if not m:
            return stats
        try:
            stats['heap'] = float(m.group('heap'))
            stats['mmap'] = float(m.group('mmap'))
            stats['used'] = float(m.group('used'))
            stats['free'] = float(m.group('free'))
            stats['releasable'] = float(m.group('releasable'))
            stats['pools'] = int(m.group('pools'))
            stats['pools_used'] = float(m.group('pools_used'))
            stats['pools_total'] = float(m.group('pools_total'))
        except (ValueError, IndexError):
            self.checks_logger.error('Failed to parse MEMSTATS line')
        return stats

    def parse_stats_response(self, response):
        stats = {}
        for line in response.split('\n'):
            line = line.strip()
            if not line:
                continue
            if line.startswith('POOLS: '):
                stats.update(self.parse_pools_line(line))
            elif line.startswith('THREADS: '):
                stats.update(self.parse_threads_line(line))
            elif line.startswith('QUEUE: '):
                stats.update(self.parse_queue_line(line))
            elif line.startswith('MEMSTATS: '):
                stats.update(self.parse_memstats_line(line))
        return stats

    def run(self):
        stats = {}

        try:
            # Pull the location of the clamd socket from the config and default
            # to CLAMD_SOCKET if it is not present
            clamd_socket = self.raw_config['Main'].get('clamd_socket',
                    CLAMD_SOCKET)
        except KeyError:
            # Should only happen if Main section of config is missing
            self.checks_logger.error('Missing sd-agent configuration')
            clamd_socket = CLAMD_SOCKET

        try:
            # Connect to the clamd socket and request STATS
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.connect(clamd_socket)
            s.send('nSTATS\n')

            # Try reading the results for at most TIMEOUT seconds
            start_time = time.time()
            raw_data = s.recv(1024)
            while raw_data.find('END') == -1:
                if time.time() - start_time >= TIMEOUT:
                    self.checks_logger.error('Timeout reading clamd response')
                    break
                raw_data += s.recv(1024)
                time.sleep(0.5)
            self.checks_logger.debug(raw_data)
            stats.update(self.parse_stats_response(raw_data))
        except socket.error:
            self.checks_logger.error('Connection to clamd failed')
            stats = {}
        self.checks_logger.debug(stats)
        return stats


if __name__ == "__main__":
    import logging
    logger = logging.getLogger("Clam")
    logger.setLevel(logging.DEBUG)
    logger.addHandler(logging.StreamHandler())
    # Fake configuration
    raw_config = {
        "clamd_socket" : CLAMD_SOCKET,
    }
    clam = Clam(None, logger, raw_config)
    clam.run()
