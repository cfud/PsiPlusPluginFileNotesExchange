include(../../psiplugin.pri)

QT += network
LIBS += -lcrypto -lgdi32

CONFIG += release
RESOURCES = file_upload.qrc

SOURCES += src/file_upload_plugin.cpp src/screenshot.cpp