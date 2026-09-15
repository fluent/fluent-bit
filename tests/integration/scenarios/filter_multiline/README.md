# `filter_multiline` Integration Scenario

This scenario exercises buffered multiline processing through a real Fluent Bit
process. It verifies that a pending multiline group is emitted during graceful
shutdown, including when the multiline emitter was already paused by its memory
buffer limit. Both operation patterns must preserve the completed group and the
pending group exactly once.
