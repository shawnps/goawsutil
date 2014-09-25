

Amazon Test Suite is Weird

* One Test is Broken -- Missing supporting files
* Files are have newlines encoded as \r\n
* No tests for "space collapsing" where headers that _internal_ whitespace
  collapsed to a single space, except when its in double-quotes
* Output does not have x-ams-content-sha256 use

