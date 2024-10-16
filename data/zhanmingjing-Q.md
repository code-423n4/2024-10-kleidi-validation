https://github.com/code-423n4/2024-10-kleidi/blob/main/src/BytesHelper.sol#L40-L43

"end <= toSlice.length" and "start < end" checked, no need to check "start < toSlice.length" any more.

    function sliceBytes(bytes memory toSlice, uint256 start, uint256 end)
        public
        pure
        returns (bytes memory)
    {
        require(
            start < toSlice.length,
            "Start index is greater than the length of the byte string"
        );
        require(
            end <= toSlice.length,
            "End index is greater than the length of the byte string"
        );
        require(start < end, "Start index not less than end index");

        uint256 length = end - start;
        bytes memory sliced = new bytes(length);

        for (uint256 i = 0; i < length; i++) {
            sliced[i] = toSlice[i + start];
        }

        return sliced;
    }


