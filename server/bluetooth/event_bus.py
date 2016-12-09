import abc
import logging
from server.exceptions import MessageTypeError


class OnBluetoothMessageListener(object, metaclass=abc.ABCMeta):
    """
    Interface for listeners that subscribe to bluetooth messages.
    """
    @abc.abstractmethod
    def on_message(self, msg_type, data=None):
        """
        Called on when a bluetooth message has been received.

        Args:
            msg_type: type of bluetooth message (as defined in protocol)
            data: data associated with the message (if applies)
        """
        pass


class BluetoothEventBus(object):
    """
    Event bus that gets sent messages via bluetooth, does some parsing and
    notifies the appropriate listeners.

    All methods work with bytes.
    """

    def __init__(self, protocol):
        """
        Create a new instance of an event bus.

        Args:
            protocol (class): class only containing attributes, which correspond
                to the message type in received bluetooth messages.
        """
        self._init_message_types(protocol)
        # TODO: go through all attrs of protocol, put their vaiues in a list,
        # create a dictionary that maps each one of the values in the list
        # to the listener list. When a message arrives, do a foreach on the
        # list and if there is a match, notify the listeners of a list.

    def subscribe(self, listener, msg_type=None):
        if msg_type is None:
            # global subscription
            self._global_listeners.append(listener)
            return

        for msg_type in msg_type:
            try:
                self._listeners[msg_type].append(listener)
            except KeyError as e:
                raise MessageTypeError(
                    '{} message type not found in the protocol'.format(msg_type))

    def process(self, data):
        """
        Process raw data received via bluetooth.

        Args:
            data (bytes): data received (via bluetooth)
        """
        for msg_type in self._msg_types:
            if data.startswith(msg_type):
                msg_len = len(msg_type)
                new_data = data[msg_len:]
                logging.info('Notifying {} listeners with data: {}'.format(
                    msg_type, new_data))
                self._notify_listeners(msg_type, new_data)

    def _init_message_types(self, protocol):
        # import pdb; pdb.set_trace()
        proto_dict = vars(protocol)
        keys = (key for key in proto_dict.keys() if not key.startswith('__'))
        self._msg_types = tuple((proto_dict[value] for value in keys))
        self._listeners = {msg_type: [] for msg_type in self._msg_types}
        self._global_listeners = []

    def _notify_listeners(self, msg_type, data):
        if len(data) == 0:
            data = None

        for listener in self._listeners[msg_type]:
            listener.on_message(msg_type, data)

        for listener in self._global_listeners:
            listener.on_message(msg_type, data)
