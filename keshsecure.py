import sys
from PyQt5 import QtWidgets
from ui import App
from database import init_db

if __name__ == '__main__':
    init_db()  # Initialiser la base de données
    app = QtWidgets.QApplication(sys.argv)
    ex = App()
    ex.show()
    sys.exit(app.exec_())
