import unittest
import settings
import server.bluetooth.protocol


class MsgType(object):
    INC = b'inc'
    DEC = b'dec'
    IGNORE = b'ignore'
    SAVE_DATA = b'save_data'
    ERROR = b'err'


class IncDecListener(object, OnBluetoothMessageListener):
    """
    Sample listener that increments or decremetns a variable,
    or simply saves the received data, based on the received event.
    """

    def __init__(self):
        self._counter = 0
        self._last_msg_type = None
        self._data = None
        self._num_calls = 0  # num of times on_message was called

    def on_message(self, msg_type, data):
        self._num_calls = self._num_calls + 1
        self._data = None  # clear previous data
        self._last_msg_type = msg_type

        if msg_type == MsgType.INC:
            self._counter = self._counter + 1

        if msg_type == MsgType.DEC:
            self._counter = self._counter - 1

        if msg_type == MsgType.SAVE_DATA:
            self._data = data


class BluetoothEventsTestCase(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_bluetooth_event_bus_sends_events(self):
        eb = BluetoothEventBus(msg_type=MsgType)

        il = IncDecListener()
        eb.subscribe(listener=il, msg_type=(
            MsgType.INC, MsgType.DEC, MsgType.IGNORE))

        # sanity check
        self.assertEqual(il._counter, 0, 'Init counter is not zero')
        self.assertEqual(il._num_calls, 0, 'Init number of calls is not zero')

        eb.process(MsgType.INC)
        self.assertEqual(il._last_msg_type, MsgType.INC)
        self.assertEqual(il._counter, 1, 'Counter not incremented')
        self.assertEqual(il._num_calls, 1)

        # make sure the event listener is not called for events it din't
        # subscribe to
        eb.process(MsgType.ERROR + b'ignore me')
        self.assertEqual(il._last_msg_type, MsgType.INC)
        self.assertEqual(il._num_calls, 1)

        expected_data = b'Produced by Dr Dre'
        eb.process(MsgType.SAVE_DATA + expected_data)
        self.assertEqual(il._last_msg_type, MsgType.SAVE_DATA)
        self.assertEqual(il._num_calls, 2)
        self.assertEqual(il._data, expected_data)

        eb.process(MsgType.ERROR + b'something went wrong')
        self.assertEqual(il._last_msg_type, MsgType.SAVE_DATA)
        self.assertEqual(il._num_calls, 2)
        self.assertIsNone(il._data)

        # now add a subscription to error mesages
        eb.subscription(il, msg_type=(MsgType.ERROR))

        eb.process(MsgType.ERROR + b'something went wrong')
        self.assertEqual(il._last_msg_type, MsgType.ERROR)
        self.assertEqual(il._num_calls, 3)

        # cerate a new listener with global subscription (all msg types)
        new_il = IncDecListener()
        eb.subscribe(new_il)

        # sanity check
        self.assertEqual(new_il._counter, 0, 'Init counter is not zero')
        self.assertEqual(new_il._num_calls, 0,
                         'Init number of calls is not zero')

        # make sure it will respond to pretty much any msg type
        eb.process(MsgType.INC)
        eb.process(MsgType.ERROR)
        eb.process(MsgType.IGNORE)
        eb.process(MsgType.DEC)
        eb.process(MsgType.SAVE_DATA)
        self.assertEqual(new_il._num_calls, 5)

        # since we're on it, let's check if the other event listener
        # got called when needed
        self.assertEqual(il._num_calls, 7)

        # make sure that if an unrecognized event is
        # received, everything still works as expected
        eb.process(
            b'fresh like uhhh, impala uhhh, chrome hydraulics, 808 druuuhms')

        self.assertEqual(new_il._num_calls, 5)

        # since we're on it, let's check if the other event listener
        # got called when needed
        self.assertEqual(il._num_calls, 7)
