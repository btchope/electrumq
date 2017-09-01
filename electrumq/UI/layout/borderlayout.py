# -*- coding: utf-8 -*-
from PyQt4.QtCore import Qt, QRect, QSize
from PyQt4.QtGui import QLayout, QWidgetItem

__author__ = 'zhouqi'


class ItemWrapper(object):
    def __init__(self, i, p):
        self.item = i
        self.position = p


class BorderLayout(QLayout):
    West, North, South, East, Center = range(5)
    MinimumSize, SizeHint = range(2)

    def __init__(self, parent=None, margin=None, spacing=-1):
        super(BorderLayout, self).__init__(parent)

        if margin is not None:
            self.setContentsMargins(margin, margin, margin, margin)

        self.setSpacing(spacing)
        self.list = []

    def __del__(self):
        l = self.takeAt(0)
        while l is not None:
            l = self.takeAt(0)

    def addItem(self, item):
        self.add(item, self.West)

    def addWidget(self, widget, position):
        self.add(QWidgetItem(widget), position)

    def expandingDirections(self):
        return Qt.Horizontal | Qt.Vertical

    def hasHeightForWidth(self):
        return False

    def count(self):
        return len(self.list)

    def itemAt(self, index):
        if index < len(self.list):
            return self.list[index].item

        return None

    def minimumSize(self):
        return self.calculateSize(self.MinimumSize)

    def setGeometry(self, rect):
        center = None
        eastWidth = 0
        westWidth = 0
        northHeight = 0
        southHeight = 0
        centerHeight = 0

        super(BorderLayout, self).setGeometry(rect)

        for wrapper in self.list:
            item = wrapper.item
            position = wrapper.position

            if position == self.North:
                item.setGeometry(QRect(rect.x(), northHeight,
                                       rect.width(), item.sizeHint().height()))

                northHeight += item.geometry().height() + self.spacing()

            elif position == self.South:
                item.setGeometry(QRect(item.geometry().x(),
                                       item.geometry().y(), rect.width(),
                                       item.sizeHint().height()))

                southHeight += item.geometry().height() + self.spacing()

                item.setGeometry(QRect(rect.x(),
                                       rect.y() + rect.height() - southHeight + self.spacing(),
                                       item.geometry().width(), item.geometry().height()))

            elif position == self.Center:
                center = wrapper

        centerHeight = rect.height() - northHeight - southHeight

        for wrapper in self.list:
            item = wrapper.item
            position = wrapper.position

            if position == self.West:
                item.setGeometry(QRect(rect.x() + westWidth,
                                       northHeight, item.sizeHint().width(), centerHeight))

                westWidth += item.geometry().width() + self.spacing()

            elif position == self.East:
                item.setGeometry(QRect(item.geometry().x(),
                                       item.geometry().y(), item.sizeHint().width(),
                                       centerHeight))

                eastWidth += item.geometry().width() + self.spacing()

                item.setGeometry(QRect(rect.x() + rect.width() - eastWidth + self.spacing(),
                                       northHeight, item.geometry().width(),
                                       item.geometry().height()))

        if center:
            center.item.setGeometry(QRect(westWidth, northHeight,
                                          rect.width() - eastWidth - westWidth, centerHeight))

    def sizeHint(self):
        return self.calculateSize(self.SizeHint)

    def takeAt(self, index):
        if index >= 0 and index < len(self.list):
            layoutStruct = self.list.pop(index)
            return layoutStruct.item

        return None

    def add(self, item, position):
        self.list.append(ItemWrapper(item, position))

    def replace(self, item1, item2):
        for each in self.list:
            if each.item is item1:
                each.item = item2

    def remove(self, item):
        be_remove_idx = None
        for idx, each in enumerate(self.list):
            if each.item is item:
                be_remove_idx = idx
        if be_remove_idx is not None:
            self.list.pop(be_remove_idx)

    def calculateSize(self, sizeType):
        totalSize = QSize()

        for wrapper in self.list:
            position = wrapper.position
            itemSize = QSize()

            if sizeType == self.MinimumSize:
                itemSize = wrapper.item.minimumSize()
            else:  # sizeType == self.SizeHint
                itemSize = wrapper.item.sizeHint()

            if position in (self.North, self.South, self.Center):
                totalSize.setHeight(totalSize.height() + itemSize.height())

            if position in (self.West, self.East, self.Center):
                totalSize.setWidth(totalSize.width() + itemSize.width())

        return totalSize
