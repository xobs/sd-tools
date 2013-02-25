About
=====
Th filters are a multi-stage process by which raw data flowing out of the
tap board is refined so that it is suitable for display.

The following sequence of events will be employed:


Joiner
------

The joiner is responsible for combining multiple NAND outputs into a
single, contiguous, unbroken NAND output.  As part of this output, it will:

* Generate one block of continuous NAND packets per sync point
* Strip out duplicate packets caused by stream replays
* Correct timestamps due to basic variation

Each "sync point" will be treated as a distinct group, with its own
synchronization to be caulculated.  If no NAND packets are present in a
sync point, then no joining will occur, aside from fixing up the clock
offset from the previous batch.

A sync point is defined as:

* The command 'ib 0'
* The command 'ib 4026531839'
* The 'hello' packet
* The end of the stream


Grouper
-------

The grouper will group multiple individual commands into one logical
command.  For example, five SD_CMD_ARG commands in a row comprises a single
SD command, and so will be grouped into a single logical command.
Similarly, NAND page reads will be grouped into logical commands with their
start-stop times recorded.


Sorter
------

Once commands are grouped logically, they must be sorted temporally.  The
sorter merely does this.
