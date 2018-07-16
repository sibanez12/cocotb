
import cocotb
from cocotb.triggers import RisingEdge, FallingEdge, ReadOnly, ReadWrite, ClockCycles, Timer
from cocotb.drivers import BusDriver
from cocotb.binary import BinaryValue

from scapy.all import Ether
import logging
logging.getLogger("scapy").setLevel(logging.ERROR)

import random
import progressbar

class AXI4StreamMaster(BusDriver):
    """
    Used to write a set of words onto an AXI4Stream interface
    """

    _signals = ["tvalid", "tdata", "tlast"]  # Write data channel
    _optional_signals = ["tready", "tkeep", "tstrb", "tid", "tdest", "tuser"]

    def __init__(self, entity, name, clock, idle_timeout=5000*1000):
        BusDriver.__init__(self, entity, name, clock)

        self.idle_timeout = idle_timeout

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

        self.pkt_cnt = 0
        self.error = False

        # For cases where there could be multiple masters on a bus, do not need for now ...
#        self.write_data_busy = Lock("%s_wbusy" % name)


    @cocotb.coroutine
    def write(self, data, keep=[1], tid=0, dest=0, user=[0], delay = 0):
        """
        Send the write data, with optional delay
        """
        # For cases where there could be multiple masters on a bus, do not need for now ...
#        yield self.write_data_busy.acquire()

        yield FallingEdge(self.clock)
        yield RisingEdge(self.clock)

        self.bus.tvalid <=  0
        self.bus.tdata  <=  data[0]
        self.bus.tlast  <=  0

        if self.has_tuser:
            self.bus.tuser  <=  user[0]

        if self.has_tkeep:
            self.bus.tkeep  <= keep[0]

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

#            yield ReadOnly()
            yield FallingEdge(self.clock)

            # do not transition to next word until tready is asserted
            while self.has_tready and not self.bus.tready.value:
                yield RisingEdge(self.clock)
                yield FallingEdge(self.clock)
            yield RisingEdge(self.clock)

#            # do not transition to next word until tready is asserted
#            if self.has_tready and not self.bus.tready.value:
#                while True:
#                    yield RisingEdge(self.clock)
##                    yield ReadOnly()
#                    yield FallingEdge(self.clock)
#                    print "self.bus.tready.value = {}".format(self.bus.tready.value)
#                    if self.bus.tready.value:
#                        yield RisingEdge(self.clock)
#                        break
##                continue
#            yield RisingEdge(self.clock)

        self.bus.tlast  <=  0;
        self.bus.tvalid <=  0;


        # For cases where there could be multiple masters on a bus, do not need for now ...
#        self.write_data_busy.release()


    @cocotb.coroutine
    def write_pkts(self, pkts, metadata, rate=None):
        """
        Write a list of scapy pkts onto the AXI4Stream bus
        rate: specified in bytes/cycle
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
            tout_trigger = Timer(self.idle_timeout)
            pkt_trigger = cocotb.fork(self.write(pkt_words, keep=pkt_keeps, user=pkt_users))
            result = yield [tout_trigger, pkt_trigger.join()]
            if result == tout_trigger:
                print 'ERROR: AXI4StreamMaster encountered a timeout at pkt {}'.format(self.pkt_cnt)
                self.error = True
                break
            self.pkt_cnt += 1

            # wait a cycle
            delay = int(len(pkt)/float(rate) - len(pkt)/float(self.data_width)) if rate is not None else 1
            for i in range(delay):
                yield RisingEdge(self.clock)


class AXI4StreamSlave(BusDriver):

    _signals = ["tvalid", "tdata", "tlast"]
    _optional_signals = ["tready", "tkeep", "tstrb", "tid", "tdest", "tuser"]


    def __init__(self, entity, name, clock, tready_delay=0, idle_timeout=5000*1000):
        BusDriver.__init__(self, entity, name, clock)

        self.tready_delay = tready_delay
        self.idle_timeout = idle_timeout
        self.has_tkeep = 'tkeep' in self.bus._signals.keys()
        self.has_tuser = 'tuser' in self.bus._signals.keys()
        self.has_tready = 'tready' in self.bus._signals.keys()
        if self.has_tready:
            self.bus.tready <= 0

        self.error = False

        self.data = []
        self.pkts = []
        self.metadata = []

    @cocotb.coroutine
    def drive_tready(self):
        """Drive the tready bus 
        """
        while not self.pkt_finished:
            self.bus.tready <= 1
            yield FallingEdge(self.clock)            
            if self.bus.tvalid.value:
                yield RisingEdge(self.clock)
                self.bus.tready <= 0
                for i in range(self.tready_delay):
                    yield RisingEdge(self.clock)
#            yield RisingEdge(self.clock)
        self.bus.tready <= 0

    @cocotb.coroutine
    def read(self):
        """Read a packet of data from the AXI4Stream bus"""

        self.pkt_finished = False
        tready_thread = cocotb.fork(self.drive_tready())

        meta = None
        # Wait for the pkt to finish
        while True:
            yield FallingEdge(self.clock)
            if self.bus.tvalid.value and self.bus.tready.value:
                tdata = self.bus.tdata.value
                tdata.big_endian = False
                if meta is None and self.has_tuser:
                    meta = self.bus.tuser.value
                    meta.big_endian = False
                    self.metadata.append(meta)
                if self.has_tkeep:
                    tkeep = self.bus.tkeep.value.get_binstr()
                    num_bytes = tkeep.count('1')
                    if num_bytes > 0:
                        self.data.append(tdata[num_bytes*8-1 : 0])
                else:
                    self.data.append(tdata)
            if self.bus.tvalid.value and self.bus.tlast.value and self.bus.tready.value:
                break
                
            yield RisingEdge(self.clock)

        self.pkt_finished = True
        yield tready_thread.join()



    @cocotb.coroutine
    def read_pkt(self, log_raw=False):
        """Read a scapy pkt"""

        self.data = []
        yield self.read()

        pkt_str = ''
        for data in self.data:
#            data.big_endian = False
            pkt_str += data.get_buff()

        if log_raw:
            self.pkts.append(pkt_str)
        else:
            try:
                pkt = Ether(pkt_str)
                self.pkts.append(pkt)
            except:
                self.pkts.append(pkt_str)


    @cocotb.coroutine
    def read_n_pkts(self, n, log_raw=False):
        """Read n scapy pkts"""
        bar = progressbar.ProgressBar(maxval=n, \
                 widgets=[progressbar.Bar('=', '[', ']'), ' ', progressbar.Percentage()])

        print 'AXI4StreamSlave receiving pkts:'
        bar.start()
        for i in range(n):
            tout_trigger = Timer(self.idle_timeout)
            pkt_trigger = cocotb.fork(self.read_pkt(log_raw))
            result = yield [tout_trigger, pkt_trigger.join()]
            if result == tout_trigger:
                print 'ERROR: AXI4StreamSlave encountered a timeout at pkt {} out of {}'.format(i, n)
                self.error = True
                break
            else:
                bar.update(i+1)
        bar.finish()

class AXI4StreamStats(BusDriver):

    _signals = ["tvalid", "tdata", "tlast"]
    _optional_signals = ["tready", "tkeep", "tstrb", "tid", "tdest", "tuser"]


    def __init__(self, entity, name, clock, idle_timeout=5000*1000):
        BusDriver.__init__(self, entity, name, clock)

        self.idle_timeout = idle_timeout
        self.has_tlast = 'tlast' in self.bus._signals.keys()
        self.has_tready = 'tready' in self.bus._signals.keys()
        self.has_tuser = 'tuser' in self.bus._signals.keys()

        self.times = []
        self.delays = []
        self.enq_delays = []
        self.metadata = []

    @cocotb.coroutine
    def record_n_start_times(self, n, counter):
        """Record the start times of n pkts using the provided counter
        """
        self.times = []
        self.metadata = []

        for i in range(n):
            tout_trigger = Timer(self.idle_timeout)
            stat_trigger = cocotb.fork(self.record_start_time(counter))
            result = yield [tout_trigger, stat_trigger.join()]
            if result == tout_trigger:
                print 'ERROR: AXI4StreamStats encountered a timeout at pkt {} out of {}'.format(i, n)
                break

    @cocotb.coroutine
    def record_start_time(self, counter):
        # wait for the first word of the pkt
        yield FallingEdge(self.clock)
        while not (self.bus.tvalid.value and self.bus.tready.value):
            yield RisingEdge(self.clock)
            yield FallingEdge(self.clock)

        # record the current cycle count
        self.times.append(counter.cnt)
        if self.has_tuser:
            meta = self.bus.tuser.value
            meta.big_endian = False
            self.metadata.append(meta)

        # wait for end of current packet
        while not (self.bus.tvalid.value and self.bus.tready.value and self.bus.tlast.value):
            yield RisingEdge(self.clock)
            yield FallingEdge(self.clock)

        yield RisingEdge(self.clock)


    @cocotb.coroutine
    def record_n_delays(self, n):
        """Record the # clock cycles between the first word of n sequential pkts
           on the AX4Stream bus"""

        self.delays = []

        # wait for the first word of the first pkt
        yield FallingEdge(self.clock)
        while not (self.bus.tvalid.value and self.bus.tready.value):
            yield RisingEdge(self.clock)
            yield FallingEdge(self.clock)

        delay = 0
        for i in range(n-1):
            # wait for end of current packet
            while not (self.bus.tvalid.value and self.bus.tready.value and self.bus.tlast.value):
                yield RisingEdge(self.clock)
                yield FallingEdge(self.clock)
                delay += 1
            yield RisingEdge(self.clock)
            yield FallingEdge(self.clock)
            delay += 1
            # wait for start of next pkt
            while not (self.bus.tvalid.value and self.bus.tready.value):
                yield RisingEdge(self.clock)
                yield FallingEdge(self.clock)
                delay += 1
            self.delays.append(delay)
            delay = 0


    @cocotb.coroutine
    def record_n_enq_delays(self, n):
        """Record the # clock cycles between tvalid asserted and the first word of the packet"""

        self.enq_delays = []

        for i in range(n):
            # wait for tvalid to be asserted
            yield FallingEdge(self.clock)
            while not self.bus.tvalid.value:
                yield RisingEdge(self.clock)
                yield FallingEdge(self.clock)
    
            delay = 0
            # wait for the end of the current packet
            while not (self.bus.tvalid.value and self.bus.tready.value and self.bus.tlast.value):
                yield RisingEdge(self.clock)
                yield FallingEdge(self.clock)
                delay += 1
            self.enq_delays.append(delay)

            yield RisingEdge(self.clock)

    @cocotb.coroutine
    def record_n_deq_delays(self, n):
        """Record the # clock cycles between tready asserted and the first word of the packet """

        self.deq_delays = []

        for i in range(n):
            # wait for tready to be asserted
            yield FallingEdge(self.clock)
            while not self.bus.tready.value:
                yield RisingEdge(self.clock)
                yield FallingEdge(self.clock)
    
            delay = 0
            # wait for the end of the current packet
            while not (self.bus.tvalid.value and self.bus.tready.value and self.bus.tlast.value):
                yield RisingEdge(self.clock)
                yield FallingEdge(self.clock)
                delay += 1
            self.deq_delays.append(delay)

            yield RisingEdge(self.clock)

class CycleCounter(object):
    """
    Simple counter to count clock cycles
    """
    def __init__(self, clock):
        self.clock = clock
        self.cnt = 0
        self.finish = False

    @cocotb.coroutine
    def start(self):
        while not self.finish:
            yield FallingEdge(self.clock)
            self.cnt += 1

