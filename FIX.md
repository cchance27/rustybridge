when we click the timeline at bottom, the number updates for chunk # but the timeline bar doesn't update.

when we click the timeline at bottom, the terminal doesnt jump to that position (clear+replay) like we do for when we click on an entry in our input event list... 

we should make sure our jump-to input event and jump-to timeline click, use the same helper to minimize code duplication... also it should be smart if we're jumping forward just play instantly the remaining chunks to get to that spot, if we click an older event from where we currently are then do the clear+replay for performance.

We should probably detect when echo is disabled to not record or <redact> input chunk for that section to protect password entry