import sqlite3
from queue import Queue
from threading import Thread

import traceback


class SQLiteThreadQueue(Thread):
    def __init__(self, path):
        super().__init__(daemon=True)
        self.path = path
        self.queue = Queue()

    def add_query(self, query, values):
        self.queue.put((query, values), block=True)

    def run(self):
        db = sqlite3.connect(self.path, timeout=60)
        while (item := self.queue.get(block=True)) is not None:
            try:
                db.execute(*item)
                db.commit()
            except:
                print(item)
                traceback.print_exc()
        db.close()

    def stop(self):
        self.queue.put(None, block=True)
        # self.queue.join()
        self.join()

    def __del__(self):
        self.stop()
