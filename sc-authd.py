#! /usr/bin/python3.6
import hashlib
import signal
import sys
import syslog
import re
import socket
import os

from threading import Lock

from smartcard import CardConnection
from smartcard.Card import Card
from smartcard.CardMonitoring import CardMonitor, CardObserver
from smartcard.util import *    


def noreturn(func: callable):
    """
    Means that callee function `func` won't return execution to caller.
    Otherwise RuntimeException will be risen
    """
    def _wrapper(*args, **kwargs):
        func(*args, **kwargs)
        raise RuntimeError("Unexpected return from dead-end function")
    return _wrapper


class CardHolder:
    """ Simple thread-safe wrapper around card data """
    def __init__(self, data=None):
        self._data = data
        self._lock = Lock()

    def read(self) -> object:
        """
        Synchronously read (return) data
        Warn! data can (in current case will) be a reference type,
        so thread safeness doesn't apply on inner fields of data
        """
        with self._lock:
            return self._data

    def set(self, data) -> object:
        """ Sets (replaces) data """
        with self._lock:
            self._data = data


class CardWatcher(CardObserver):
    """A simple reader observer that is notified
    when readers are added/removed from the system and
    prints the list of readers
    """
    def __init__(self, holder: CardHolder):
        super().__init__()
        self._holder = holder
        
    def update(self, observable, actions: ([Card], [Card])) -> None:
        """ Triggers every time when card reader state changes (card insert or remove) """

        (added_cards, removed_cards) = actions
        try:
            for card in added_cards:
                syslog.syslog(syslog.LOG_NOTICE, "Inserted card with ATR {}".format(toHexString(card.atr)))
            for card in removed_cards:
                syslog.syslog(syslog.LOG_NOTICE, "Removed card with ATR {}".format(toHexString(card.atr)))

            if len(removed_cards) > 0:
                self._process_remove_card(removed_cards[0])
            if len(added_cards) > 0:
                self._process_add_card(added_cards[0])
        except Exception as e:
            syslog.syslog(syslog.LOG_DEBUG, "{}: {}".format(e.__class__.__name__, e))
            self._holder.set((None, None))

    def _process_remove_card(self, card: Card) -> None:
        """ Clears card cache """
        if self._holder.read()[1] == toHexString(card.atr):
            self._holder.set(("", None))

    def _process_add_card(self, card: Card) -> None:
        """
        Reads card's PAN and ATR and saves in a cache
        Supports only several Mastercard cards
        """
        connection = card.createConnection()
        connection.connect()

        syslog.syslog(syslog.LOG_INFO, "Card connected. ATR: {}, protocol: {}"
                      .format(toHexString(card.atr), connection.getProtocol()))

        # Initialize card. Select Payment System Environment - 2PAY.SYS.DDF01
        self._send_apdu_T0(connection, [0x00, 0xA4, 0x04, 0x00, 0x0E, 0x32, 0x50, 0x41, 0x59, 0x2E,
                                        0x53, 0x59, 0x53, 0x2E, 0x44, 0x44, 0x46, 0x30, 0x31, 0x00])

        # Select AID - Mastercard International (A0 00 00 00 04 10 10)
        self._send_apdu_T0(connection, [0x00, 0xA4, 0x04, 0x00, 0x07, 0xA0, 0x00, 0x00, 0x00, 0x04, 0x10, 0x10])

        # I had to comment this obscure magic straight away after playing with it.
        # Because now I can't remember what it means
        self._send_apdu_T0(connection, [0x80, 0xA8, 0x00, 0x00, 0x02, 0x83, 0x00, 0x00])

        # Read file which contains card info (I need only PAN)
        resp = self._send_apdu_T0(connection, [0x00, 0xB2, 0x01, 0x2C, 0x00])

        if resp is None:
            self._holder.set((None, None))
            syslog.syslog(syslog.LOG_INFO, "Reading PAN failed")
        else:
            pan = self._parse_pan(toHexString(resp))
            self._holder.set((pan, toHexString(card.atr)))
            syslog.syslog(syslog.LOG_INFO, "Reading PAN successful")

        connection.disconnect()

    @staticmethod
    def _send_apdu_T0(connection: CardConnection, apdu: [int]) -> list or None:
        """ Send APDU (command) to the card and try to read its response (T0 protocol) """
        try:
            sw2 = connection.transmit(apdu)[2]
            response, sw1, sw2 = connection.transmit([0x00, 0xC0, 0x00, 0x00, sw2])
            return response
        except Exception:
            return None

    @staticmethod
    def _parse_pan(card_response: str) -> str or None:
        """ Find PAN by specific signature """
        match = re.search("5A08(.{16})", card_response.replace(" ", ""))
        if len(match.groups()) > 0:
            return match.group(1)
        return None


class AuthD:
    """
    Smart Card Authentication daemon wrapper
    Supports start/restart/stop and communication through socket
    """
    SOCK_FILE = "/var/run/sc-authd.socket"
    PID_FILE = "/var/run/sc-authd.pid"

    def __init__(self):
        self._pan_monitor = None
        self._card_monitor = None
        self._latest_info = None
        self._watcher = None
        self._sock = None

    def start(self) -> None:
        """ Do daemonization and then init all requirements - sockets, card service, etc. """
        self._turn_daemon()

        self._pan_monitor = CardHolder()

        if os.path.exists(AuthD.SOCK_FILE):
            os.unlink(AuthD.SOCK_FILE)

        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.bind(AuthD.SOCK_FILE)
        #os.chmod(AuthD.SOCK_FILE, 0o777)

        self._card_monitor = CardMonitor()
        self._watcher = CardWatcher(self._pan_monitor)
        self._card_monitor.addObserver(self._watcher)

        # Pretty normal signal hooks set to shutdown this daemon
        signal.signal(signal.SIGABRT, self._shutdown)
        signal.signal(signal.SIGTERM, self._shutdown)
        signal.signal(signal.SIGQUIT, self._shutdown)
        signal.signal(signal.SIGINT, self._shutdown)

        self.run()

    def restart(self) -> None:
        """ Simply calls AuthD#stop and AuthD#start then """
        self.stop()
        self.start()

    def stop(self) -> None:
        """ Tries to read daemon's PID file and kill it with SIGQUIT """
        try:
            with open(AuthD.PID_FILE, "rt") as pid_file:
                pid_s = pid_file.readline().strip()
                os.kill(int(pid_s), signal.SIGQUIT)
        except FileNotFoundError:
            syslog.syslog(syslog.LOG_WARNING, "Can't stop. Daemon is not running")
        except IOError as error:
            syslog.syslog(syslog.LOG_ERR, "Can't stop. {}".format(error))

    def run(self) -> None:
        """ Main loop method. Listens to the socket and execute commands passed through it """
        while True:
            self._sock.listen(1)
            conn, _ = self._sock.accept()
            command = conn.recv(128).decode("utf-8")
            if command == "get_pan":
                if self._pan_monitor.read() is None:
                    pan = ""
                else:
                    pan = self._pan_monitor.read()[0] or ""  # cause ...[0] can be None
                sha = hashlib.sha3_512()
                sha.update(pan.encode("utf-8"))
                conn.send(sha.hexdigest().encode("utf-8"))

    @noreturn
    def _shutdown(self, signum: int, _: None):
        """ Close all handles, stops card monitor """
        self._card_monitor.deleteObserver(self._watcher)
        self._sock.close()
        if os.path.isfile(AuthD.PID_FILE):
            os.unlink(AuthD.PID_FILE)

        if os.path.exists(AuthD.SOCK_FILE):
            os.unlink(AuthD.SOCK_FILE)
        syslog.syslog(syslog.LOG_INFO, "Stopped by sig #{}".format(signum))

        sys.exit(0)

    def _turn_daemon(self) -> None:
        """ Awakens Cthulhu """
        self._fork()

        os.chdir("/")
        os.setsid()
        os.umask(0)

        self._fork()

        sys.stdout.flush()
        sys.stderr.flush()

        stdin = open(os.devnull, "rt")
        stdout = open(os.devnull, "wt")
        stderr = open(os.devnull, "wt")
        os.dup2(stdin.fileno(), sys.stdin.fileno())
        os.dup2(stdout.fileno(), sys.stdout.fileno())
        os.dup2(stderr.fileno(), sys.stderr.fileno())

        pid = os.getpid()
        if os.path.isfile(AuthD.PID_FILE):
            os.unlink(AuthD.PID_FILE)

        with open(AuthD.PID_FILE, "wt") as pidfile:
            pidfile.write(str(pid))

    def _fork(self) -> None:
        """ Just forks """
        try:
            pid = os.fork()
            if pid != 0:
                sys.exit(0)
        except OSError as error:
            syslog.syslog(syslog.LOG_CRIT, "Can't daemonize", error)
            sys.exit(1)


def main():
    authd = AuthD()

    commands = {
        "start": authd.start,
        "stop": authd.stop,
        "restart": authd.restart,
    }

    if len(sys.argv) > 1:
        try:
            commands[sys.argv[1]]()
        except KeyError:
            print("Illegal command `{}`".format(sys.argv[1]))
    else:
        authd.start()


if __name__ == "__main__":
    main()

