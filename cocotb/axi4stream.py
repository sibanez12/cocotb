
import cocotb
from cocotb.triggers import RisingEdge, ReadOnly, ReadWrite, ClockCycles
from cocotb.drivers import BusDriver
from cocotb.binary import BinaryValue

from scapy.all import Ether
import logging
logging.getLogger("scapy").setLevel(logging.ERROR)

class AXI4StreamMaster(BusDriver):
    """
    Used to write a set of words onto an AXI4Stream interface
    """

    _signals = ["tvalid", "tdata", "tlast"]  # Write data channel
    _optional_signals = ["tready", "tkeep", "tstrb", "tid", "tdest", "tuser"]

    def __init__(self, entity, name, clock):
        BusDriver.__init__(self, entity, name, clock)

        self.data_width = len(self.bus.tdata) # bits

        self.data_width_bytes = self.data_width / 8

        # Drive default values onto bus
        self.bus.tvalid.setimmediatevalue(0)
        self.bus.tdata.setimmediatevalue(BinaryValue(value = 0x0, bits = self.data_width, bigEndian = False))
        self.bus.tlast.setimmediatevalue(0)

        self.has_tkeep = 'tkeep' in self.bus._signals.keys()
        self.has_tuser = 'tuser' in self.bus._signals.keys()
        self.has_tready = 'tready' in self.bus._signals.keys()

        if self.has_tkeep:
            self.keep_width = len(self.bus.tkeep) # bits
            self.bus.tkeep.setimmediatevalue(0)

        if self.has_tuser:
            self.user_width = len(self.bus.tuser) # bits
            self.bus.tuser.setimmediatevalue(BinaryValue(value = 0x0, bits = self.user_width, bigEndian = False))

        # For cases where there could be multiple masters on a bus, do not need for now ...
#        self.write_data_busy = Lock("%s_wbusy" % name)

    @cocotb.coroutine
    def write(self, data, keep=[1], tid=0, dest=0, user=[0], delay = 0):
        """
        Send the write data, with optional delay
        """
        # For cases where there could be multiple masters on a bus, do not need for now ...
#        yield self.write_data_busy.acquire()
        self.bus.tvalid <=  0
        self.bus.tdata  <=  data[0]
        self.bus.tlast  <=  0

        if self.has_tuser:
            self.bus.tuser  <=  user[0]

        if self.has_tkeep:
            self.bus.tkeep  <= keep[0]

#        yield RisingEdge(self.clock)

        # every clock cycle update the data
        for i in range (len(data)):
            self.bus.tdata  <= data[i]
            if self.has_tkeep:
                self.bus.tkeep <= keep[i]
            if self.has_tuser:
                self.bus.tuser <= user[i]
            for j in range(delay):
                self.bus.tvalid <=  0
                yield RisingEdge(self.clock)
            self.bus.tvalid <=  1

            if i >= len(data) - 1:
                self.bus.tlast  <=  1;

            yield ReadOnly()

            # do not transition to next word until tready is asserted
            if self.has_tready and not self.bus.tready.value:
                while True:
                    yield RisingEdge(self.clock)
                    yield ReadOnly()
                    if self.bus.tready.value:
                        yield RisingEdge(self.clock)
                        break
                continue
            yield RisingEdge(self.clock)

        self.bus.tlast  <=  0;
        self.bus.tvalid <=  0;


        # For cases where there could be multiple masters on a bus, do not need for now ...
#        self.write_data_busy.release()

    @cocotb.coroutine
    def write_pkts(self, pkts, metadata):
        """
        Write a list of scapy pkts onto the AXI4Stream bus
        """
        for (pkt, meta) in zip(pkts, metadata):
            pkt_str = str(pkt)
            pkt_words = []
            pkt_keeps = []
            while len(pkt_str) > self.data_width_bytes:
                # build the word
                word = BinaryValue(bits = self.data_width, bigEndian=False)
                word.set_buff(pkt_str[0:self.data_width_bytes])
                pkt_words.append(word)
                # build tkeep
                keep = BinaryValue(bits = self.keep_width, bigEndian=False)
                keep.set_binstr('1'*self.keep_width)
                pkt_keeps.append(keep)
                # update pkt_str
                pkt_str = pkt_str[self.data_width_bytes:]
            # build the last word
            word = BinaryValue(bits = self.data_width, bigEndian=False)
            word.set_buff(pkt_str + '\x00'*(self.data_width_bytes-len(pkt_str)))
            pkt_words.append(word)
            # build the final tkeep
            keep = BinaryValue(bits = self.keep_width, bigEndian=False)
            keep.set_binstr('0'*(self.keep_width-len(pkt_str)) + '1'*len(pkt_str))
            pkt_keeps.append(keep)
            # build tuser
            pkt_users = [meta] + [0]*(len(pkt_words)-1)
            # send the pkt
            yield self.write(pkt_words, keep=pkt_keeps, user=pkt_users)
            # wait a cycle
            yield RisingEdge(self.clock)


class AXI4StreamSlave(BusDriver):

    _signals = ["tvalid", "tdata", "tlast"]
    _optional_signals = ["tready", "tkeep", "tstrb", "tid", "tdest", "tuser"]


    def __init__(self, entity, name, clock):
        BusDriver.__init__(self, entity, name, clock)

        self.has_tkeep = 'tkeep' in self.bus._signals.keys()
        self.has_tuser = 'tuser' in self.bus._signals.keys()
        self.has_tready = 'tready' in self.bus._signals.keys()
        if self.has_tready:
            self.bus.tready <= 1

        self.data = []
        self.pkts = []
        self.metadata = []

    @cocotb.coroutine
    def read(self):
        """Read a packet of data from the AXI4Stream bus"""

        # wait for valid
        yield ReadOnly()
        while not self.bus.tvalid.value:
            yield RisingEdge(self.clock)
            yield ReadOnly()

        meta = None
        # Wait for the pkt to finish
        while True:
            if self.bus.tvalid.value:
                tdata = self.bus.tdata.value
                tdata.big_endian = False
                if meta is None and self.has_tuser:
                    meta = self.bus.tuser.value
                    meta.big_endian = False
                    self.metadata.append(meta)
                if self.has_tkeep:
                    tkeep = self.bus.tkeep.value.get_binstr()
                    num_bytes = tkeep.count('1')
                    self.data.append(tdata[num_bytes*8-1 : 0])
                else:
                    self.data.append(tdata)
            if self.bus.tvalid.value and self.bus.tlast.value:
                break
            yield RisingEdge(self.clock)
            yield ReadOnly()

    @cocotb.coroutine
    def read_pkt(self):
        """Read a scapy pkt"""

        self.data = []
        yield self.read()

        pkt_str = ''
        for data in self.data:
#            data.big_endian = False
            buff = data.get_buff()
            pkt_str += data.get_buff()
        pkt = Ether(pkt_str)            
        self.pkts.append(pkt)




