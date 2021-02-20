import idc
import idautils
import idaapi

import winsound
from datetime import datetime
import time
import string
from textwrap import wrap

#
# #
# # #
# # # # Entitlement Finder
# # #
# #
#

# global variables (in python u dont really need to declare them, but just for clarifying)

# user input

verbose = False
sound = False

FirstSegment_VirtualAddress = 0x00000000

SecondSegment_VirtualAddress = 0x00000000

# program input

EntitlementLength = 32

# program variables (shouldn't be changed in most cases)

BytesLength = 2
SizesLength = 8
AddressesLength = 8

successes = 0
success_text = None

failures = 0
failure_text = None

heads = None
heads_amount = None
heads_index = None
previous_head = None
current_head = None
next_head = None

cmd = None
cmd_length = None
cmd_fixed = None
cmd_fixed_length = None
cmd_fixed_splitted = None
cmd_fixed_splitted_amount = None
cmd_fixed_splitted_index = None
cmd_fixed_splitted_cell = None
cmd_fixed_splitted_cell_length = None
cmd_fixed_splitted_cell_index = None

position = None

entitlement_bytes_amount = EntitlementLength / 2

entitlement_allowed_characters = None
entitlement_allowed_characters_matches = 0

suggested_entitlement_allowed_characters = None
suggested_entitlement_allowed_characters_matches = 0

suggested_hardcore_entitlement_allowed_characters_matches = 0

sequence_bytes = None
sequence_bytes_address = None
sequence_bytes_original_amount = None
sequence_bytes_amount = None
sequence_bytes_offset = None
sequence_bytes_index = None
sequence_byte = None


def CheckHexText(source, length, add_0x):  # returns the hex text
    source_hex = str(hex(source)[2:])
    source_hex_length = len(source_hex)
    source_hex_index = None
    source_hex_cell = None

    for source_hex_index in range(0, source_hex_length):
        source_hex_cell = source_hex[source_hex_index]

        if (source_hex_cell in string.hexdigits) is False:
            source_hex = source_hex[:source_hex_index]

            break

    result = str(source_hex.zfill(length))

    if add_0x is True:
        result = "0x" + result

    return result


def WaitForInitialAutoanalysis():
    idc.auto_wait()


def CompletionSound():
    frequencies = [420, 430, 440]
    frequency = None

    duration = 500

    for frequency in frequencies:
        winsound.Beep(frequency, duration)
        time.sleep(duration / 1000)


def CheckHeads(start_address, end_address):  # returns the heads in the range
    result = None

    current_result = []

    heads = idautils.Heads(start_address, end_address)

    for head in heads:
        current_result.append(int(head))

    result = current_result

    return result


def CheckCommand(address):  # returns the command
    result = str(idc.GetDisasm(address))

    return result


def CheckByte(address):  # returns the byte from the address
    result = int(idc.GetOriginalByte(address))

    return result


def CheckSequenceBytesAmount(sequence_bytes_address):  # returns the sequence bytes amount
    result = None

    current_result = int(idc.ItemSize(sequence_bytes_address))

    if current_result <= 0:
        current_result = 1

    result = current_result

    return result


def CreateSequence(address, amount):  # returns True if succeed to create the sequence, False if didn't
    # if the amount is None then checking the sequence amount using the CheckSequenceBytesAmount function

    result = None

    # Global Variables

    # global verbose
    # global sound

    # global FirstSegment_VirtualAddress

    # global SecondSegment_VirtualAddress

    # global EntitlementLength

    global BytesLength
    global SizesLength
    global AddressesLength

    # global successes
    # global success_text

    # global failures
    # global failure_text

    # global heads
    # global heads_amount
    # global heads_index
    # global previous_head
    # global current_head
    # global next_head

    # global cmd
    # global cmd_length
    # global cmd_fixed
    # global cmd_fixed_length
    # global cmd_fixed_splitted
    # global cmd_fixed_splitted_amount
    # global cmd_fixed_splitted_index
    # global cmd_fixed_splitted_cell
    # global cmd_fixed_splitted_cell_length
    # global cmd_fixed_splitted_cell_index

    # global position

    # global entitlement_bytes_amount

    # global entitlement_allowed_characters
    # global entitlement_allowed_characters_matches

    # global suggested_entitlement_allowed_characters
    # global suggested_entitlement_allowed_characters_matches

    # global suggested_hardcore_entitlement_allowed_characters_matches

    global sequence_bytes
    global sequence_bytes_address
    global sequence_bytes_original_amount
    global sequence_bytes_amount
    global sequence_bytes_offset
    global sequence_bytes_index
    global sequence_byte

    # Function Variables

    method_found = False

    # Start

    if sequence_bytes_address == address and sequence_bytes_original_amount == amount:
        method_found = True
    else:
        sequence_bytes_original_amount = amount

        sequence_bytes = None
        sequence_bytes_address = address
        sequence_bytes_amount = None
        sequence_bytes_offset = None
        sequence_bytes_index = None
        sequence_byte = None

        if sequence_bytes_original_amount is not None:
            sequence_bytes_amount = sequence_bytes_original_amount
        else:
            sequence_bytes_amount = CheckSequenceBytesAmount(sequence_bytes_address)

        # print(str(sequence_bytes_amount))

        if sequence_bytes_amount is not None and sequence_bytes_amount > 0:
            sequence_bytes = []

            for sequence_bytes_index in range(0, sequence_bytes_amount):
                sequence_byte = None

                sequence_bytes.append(sequence_byte)

            method_found = True

    result = method_found

    return result


def CheckSequenceByte(offset):  # offset from start (0 goes for first cell, 1 for second, etc), returns the sequence byte
    result = None

    # Global Variables

    # global verbose
    # global sound

    # global FirstSegment_VirtualAddress

    # global SecondSegment_VirtualAddress

    # global EntitlementLength

    global BytesLength
    global SizesLength
    global AddressesLength

    # global successes
    # global success_text

    # global failures
    # global failure_text

    # global heads
    # global heads_amount
    # global heads_index
    # global previous_head
    # global current_head
    # global next_head

    # global cmd
    # global cmd_length
    # global cmd_fixed
    # global cmd_fixed_length
    # global cmd_fixed_splitted
    # global cmd_fixed_splitted_amount
    # global cmd_fixed_splitted_index
    # global cmd_fixed_splitted_cell
    # global cmd_fixed_splitted_cell_length
    # global cmd_fixed_splitted_cell_index

    # global position

    # global entitlement_bytes_amount

    # global entitlement_allowed_characters
    # global entitlement_allowed_characters_matches

    # global suggested_entitlement_allowed_characters
    # global suggested_entitlement_allowed_characters_matches

    # global suggested_hardcore_entitlement_allowed_characters_matches

    global sequence_bytes
    global sequence_bytes_address
    # global sequence_bytes_original_amount
    global sequence_bytes_amount
    # global sequence_bytes_offset
    # global sequence_bytes_index
    # global sequence_byte

    # Function Variables

    current_result = None

    # Start

    if offset >= 0 and offset < sequence_bytes_amount:
        if sequence_bytes[offset] is not None:
            current_result = sequence_bytes[offset]
        else:
            current_result = CheckByte(sequence_bytes_address + offset)

            sequence_bytes[offset] = current_result

    result = current_result

    return result


def CheckSequenceBytesText(direction):  # returns the sequence bytes text, None in case of not finding any
    # gets direction, True goes for first to last byte, False goes for last to first byte

    result = None

    # Global Variables

    # global verbose
    # global sound

    # global FirstSegment_VirtualAddress

    # global SecondSegment_VirtualAddress

    # global EntitlementLength

    global BytesLength
    global SizesLength
    global AddressesLength

    # global successes
    # global success_text

    # global failures
    # global failure_text

    # global heads
    # global heads_amount
    # global heads_index
    # global previous_head
    # global current_head
    # global next_head

    # global cmd
    # global cmd_length
    # global cmd_fixed
    # global cmd_fixed_length
    # global cmd_fixed_splitted
    # global cmd_fixed_splitted_amount
    # global cmd_fixed_splitted_index
    # global cmd_fixed_splitted_cell
    # global cmd_fixed_splitted_cell_length
    # global cmd_fixed_splitted_cell_index

    # global position

    # global entitlement_bytes_amount

    # global entitlement_allowed_characters
    # global entitlement_allowed_characters_matches

    # global suggested_entitlement_allowed_characters
    # global suggested_entitlement_allowed_characters_matches

    # global suggested_hardcore_entitlement_allowed_characters_matches

    # global sequence_bytes
    # global sequence_bytes_address
    # global sequence_bytes_original_amount
    global sequence_bytes_amount
    # global sequence_bytes_offset
    global sequence_bytes_index
    global sequence_byte

    # Function Variables

    current_result = None

    # Start

    if sequence_bytes_amount > 0:
        if direction is True:
            sequence_bytes_index = 0
        else:
            sequence_bytes_index = sequence_bytes_amount - 1

        while (
            direction is True and sequence_bytes_index < sequence_bytes_amount
            or direction is False and sequence_bytes_index >= 0
        ):
            sequence_byte = CheckSequenceByte(sequence_bytes_index)

            if sequence_byte is not None:
                if current_result is None:
                    current_result = ""

                current_result += CheckHexText(sequence_byte, BytesLength, (current_result == ""))
            else:
                break

            if direction is True:
                sequence_bytes_index += 1
            else:
                sequence_bytes_index -= 1

    result = current_result

    return result


def check_entitlement_allowed_characters():
    # Global Variables

    # global verbose
    # global sound

    # global FirstSegment_VirtualAddress

    # global SecondSegment_VirtualAddress

    # global EntitlementLength

    global BytesLength
    global SizesLength
    global AddressesLength

    # global successes
    # global success_text

    # global failures
    # global failure_text

    # global heads
    # global heads_amount
    # global heads_index
    # global previous_head
    # global current_head
    # global next_head

    # global cmd
    # global cmd_length
    # global cmd_fixed
    # global cmd_fixed_length
    # global cmd_fixed_splitted
    # global cmd_fixed_splitted_amount
    # global cmd_fixed_splitted_index
    # global cmd_fixed_splitted_cell
    # global cmd_fixed_splitted_cell_length
    # global cmd_fixed_splitted_cell_index

    # global position

    # global entitlement_bytes_amount

    global entitlement_allowed_characters
    # global entitlement_allowed_characters_matches

    global suggested_entitlement_allowed_characters
    # global suggested_entitlement_allowed_characters_matches

    # global suggested_hardcore_entitlement_allowed_characters_matches

    # global sequence_bytes
    # global sequence_bytes_address
    # global sequence_bytes_original_amount
    # global sequence_bytes_amount
    # global sequence_bytes_offset
    # global sequence_bytes_index
    # global sequence_byte

    # Start

    entitlement_allowed_characters = (
        [
            '0'
            , '1'
            , '2'
            , '3'
            , '4'
            , '5'
            , '6'
            , '7'
            , '8'
            , '9'
            , 'A'
            , 'B'
            , 'C'
            , 'D'
            , 'E'
            , 'F'
            , 'G'
            , 'H'
            , 'I'
            , 'J'
            , 'K'
            , 'L'
            , 'M'
            , 'N'
            , 'O'
            , 'P'
            , 'Q'
            , 'R'
            , 'S'
            , 'T'
            , 'U'
            , 'V'
            , 'W'
            , 'X'
            , 'Y'
            , 'Z'
            , 'a'
            , 'b'
            , 'c'
            , 'd'
            , 'e'
            , 'f'
            , 'g'
            , 'h'
            , 'i'
            , 'j'
            , 'k'
            , 'l'
            , 'm'
            , 'n'
            , 'o'
            , 'p'
            , 'q'
            , 'r'
            , 's'
            , 't'
            , 'u'
            , 'v'
            , 'w'
            , 'x'
            , 'y'
            , 'z'
        ]
    )

    suggested_entitlement_allowed_characters = (
        [
            '!'
            , '"'
            , '#'
            , '$'
            , '%'
            , '&'
            , '\''
            , '('
            , ')'
            , '*'
            , '+'
            , ','
            , '-'
            , '.'
            , '/'
            , ':'
            , ';'
            , '<'
            , '='
            , '>'
            , '?'
            , '@'
            , '['
            , '\\'
            , ']'
            , '^'
            , '_'
            , '`'
            , '{'
            , '|'
            , '}'
            , '~'
        ]
    )


def check_entitlement():  # returns -1 in case of failure, 0 in case of not finding a match, and 1 in case of success
    result = None

    # Global Variables

    global verbose
    # global sound

    # global FirstSegment_VirtualAddress

    # global SecondSegment_VirtualAddress

    global EntitlementLength

    global BytesLength
    global SizesLength
    global AddressesLength

    global successes
    global success_text

    # global failures
    global failure_text

    # global heads
    # global heads_amount
    # global heads_index
    # global previous_head
    global current_head
    # global next_head

    # global cmd
    # global cmd_length
    # global cmd_fixed
    # global cmd_fixed_length
    global cmd_fixed_splitted
    global cmd_fixed_splitted_amount
    # global cmd_fixed_splitted_index
    global cmd_fixed_splitted_cell
    global cmd_fixed_splitted_cell_length
    # global cmd_fixed_splitted_cell_index

    global position

    global entitlement_bytes_amount

    global entitlement_allowed_characters
    global entitlement_allowed_characters_matches

    global suggested_entitlement_allowed_characters
    global suggested_entitlement_allowed_characters_matches

    global suggested_hardcore_entitlement_allowed_characters_matches

    # global sequence_bytes
    global sequence_bytes_address
    # global sequence_bytes_original_amount
    global sequence_bytes_amount
    global sequence_bytes_offset
    # global sequence_bytes_index
    # global sequence_byte

    # Function Variables

    SequenceBytesText = None

    wrapped_entitlement = None
    wrapped_entitlement_cell = None
    wrapped_entitlement_cell_character = None

    possible_entitlement = None
    possible_entitlement_level = None
    possible_entitlement_text = None
    possible_entitlement_hex_text = None

    method_found = False
    error_found = False

    # Start

    if cmd_fixed_splitted_amount == 2:
        command = cmd_fixed_splitted[0]

        if command == "xmmword":
            if cmd_fixed_splitted_cell_length - 1 == EntitlementLength:
                for cmd_fixed_splitted_cell_index in range(0, cmd_fixed_splitted_cell_length):
                    if cmd_fixed_splitted_cell[cmd_fixed_splitted_cell_index] in string.hexdigits:
                        continue
                    elif cmd_fixed_splitted_cell[cmd_fixed_splitted_cell_index] == 'h':
                        if cmd_fixed_splitted_cell_index > 0:
                            if cmd_fixed_splitted_cell_index == cmd_fixed_splitted_cell_length - 1:
                                method_found = True

                        break
                    else:
                        break

                if method_found is True:
                    method_found = False

                    CreateSequence(current_head, None)  # no need to check for the result, assuming it is True

                    if sequence_bytes_amount != entitlement_bytes_amount:
                        failure_text = (
                            "the sequence bytes amount"
                            + ' ' + str(sequence_bytes_amount)
                            + ' ' + "isn't the same as the entitlement bytes amount"
                            + ' ' + str(entitlement_bytes_amount)
                        )

                        error_found = True
                    else:
                        SequenceBytesText = CheckSequenceBytesText(True)

                        if SequenceBytesText is None:
                            failure_text = ("the sequence bytes text is empty")

                            error_found = True
                        else:
                            wrapped_entitlement = (
                                wrap(
                                    cmd_fixed_splitted_cell[0:cmd_fixed_splitted_cell_length - 1]  # the hex number as a string without the 'h' at the end
                                    , 2
                                )  # converting the string to a string list with each cell having 2 number characters
                            )

                            possible_entitlement_level = 0
                            possible_entitlement_text = ""

                            for wrapped_entitlement_cell in wrapped_entitlement:
                                wrapped_entitlement_cell_character = chr(int(wrapped_entitlement_cell, 16))

                                if (wrapped_entitlement_cell_character in entitlement_allowed_characters) is True:
                                    possible_entitlement_text += wrapped_entitlement_cell_character
                                else:
                                    if (wrapped_entitlement_cell_character in suggested_entitlement_allowed_characters) is True:
                                        possible_entitlement_text += wrapped_entitlement_cell_character

                                        if possible_entitlement_level == 0:
                                            possible_entitlement_level = 1
                                    else:
                                        if possible_entitlement_level <= 1:
                                            possible_entitlement_level = 2

                            possible_entitlement = (
                                int(
                                    "".join(
                                        wrapped_entitlement[::-1]  # reversing the list
                                    )  # converting the list to a string
                                    , 16
                                )  # converting the string as a hex number to int
                            )

                            possible_entitlement_text = possible_entitlement_text[::-1]
                            possible_entitlement_hex_text = CheckHexText(possible_entitlement, EntitlementLength, True)

                            if possible_entitlement_hex_text != SequenceBytesText:
                                failure_text = (
                                    "the sequence bytes text"
                                    + ' ' + str(SequenceBytesText)
                                    + ' ' + "isn't the same as the possible entitlement bytes hex text"
                                    + ' ' + str(possible_entitlement_hex_text)
                                )

                                error_found = True
                            else:
                                success_text = "Found possible entitlement"

                                success_text += (
                                    '\t' + "level:" + ' '
                                    + (
                                        "entitlement allowed characters"
                                        if possible_entitlement_level == 0
                                        else (
                                            "suggested entitlement allowed characters"
                                            if possible_entitlement_level == 1
                                            else "suggested hardcore entitlement allowed characters"
                                        )
                                    )
                                )

                                success_text += '\t' + "address:" + ' ' + CheckHexText(sequence_bytes_address, AddressesLength, True)

                                if verbose is True:
                                    success_text += (
                                        '\t' + "command:" + ' ' + '\t'.join(cmd_fixed_splitted)
                                        + '\t' + "position:" + ' ' + str(position) + ' ' + "out of:" + ' ' + str(cmd_fixed_splitted_amount)
                                    )

                                success_text += (
                                    '\t' + "possible entitlement:" + ' ' + possible_entitlement_hex_text
                                    + '\t' + "possible entitlement text:" + ' ' + possible_entitlement_text
                                )

                                if verbose is True:
                                    success_text += (('\t' + "sequence bytes:" + ' ' + SequenceBytesText) if SequenceBytesText is not None else "")

                                print(success_text)

                                if possible_entitlement_level == 0:
                                    entitlement_allowed_characters_matches += 1
                                elif possible_entitlement_level == 1:
                                    suggested_entitlement_allowed_characters_matches += 1
                                else:
                                    suggested_hardcore_entitlement_allowed_characters_matches += 1

                                successes += 1

                                method_found = True

    if method_found is True:
        result = 1
    elif error_found is True:
        result = -1
    else:
        result = 0

    return result


def fix_addresses():
    # Global Variables

    # global verbose
    # global sound

    global FirstSegment_VirtualAddress

    global SecondSegment_VirtualAddress

    # global EntitlementLength

    global BytesLength
    global SizesLength
    global AddressesLength

    # global successes
    # global success_text

    global failures
    global failure_text

    global heads
    global heads_amount
    global heads_index
    global previous_head
    global current_head
    global next_head

    global cmd
    global cmd_length
    global cmd_fixed
    global cmd_fixed_length
    global cmd_fixed_splitted
    global cmd_fixed_splitted_amount
    global cmd_fixed_splitted_index
    global cmd_fixed_splitted_cell
    global cmd_fixed_splitted_cell_length
    global cmd_fixed_splitted_cell_index

    global position

    # global entitlement_bytes_amount

    # global entitlement_allowed_characters
    # global entitlement_allowed_characters_matches

    # global suggested_entitlement_allowed_characters
    # global suggested_entitlement_allowed_characters_matches

    # global suggested_hardcore_entitlement_allowed_characters_matches

    # global sequence_bytes
    # global sequence_bytes_address
    # global sequence_bytes_original_amount
    # global sequence_bytes_amount
    # global sequence_bytes_offset
    # global sequence_bytes_index
    # global sequence_byte

    # Function Variables

    check_entitlement_result = None

    SequenceBytesText = None

    error_message = None

    method_found = False
    error_found = False

    # Start

    #
    # #
    # # # going through all of the functions/commands in all of the addresses from the first segment virtual address
    # # # to the segment after the mem hole mapped virtual address + its file size (not including the last one since it's an address of the next segment)
    # #
    #

    # going through all of the heads from first segment virtual address
    # to the segment before mem hole virtual address (not including the last one since it's an address of the next segment)

    print("")
    print("parsing addresses between the first segment to the segment before the memory hole")

    heads = CheckHeads(FirstSegment_VirtualAddress, SecondSegment_VirtualAddress - 1)
    heads_amount = len(heads)

    # heads_amount = 0

    check_entitlement_allowed_characters()

    for heads_index in range(0, heads_amount):
        previous_head = None
        current_head = None
        next_head = None

        if heads_index > 0:
            previous_head = heads[heads_index - 1]

        current_head = heads[heads_index]

        if heads_index < heads_amount - 1:
            next_head = heads[heads_index + 1]

        # print(CheckHexText(previous_head, AddressesLength, True))
        # print(CheckHexText(current_head, AddressesLength, True))
        # print(CheckHexText(next_head, AddressesLength, True))

        cmd = CheckCommand(current_head)

        if cmd is not None:
            cmd_length = len(cmd)

            if cmd_length > 0:
                # print(cmd)

                failure_text = None

                cmd_fixed = None
                cmd_fixed_length = None
                cmd_fixed_splitted = None
                cmd_fixed_splitted_amount = None
                cmd_fixed_splitted_index = None
                cmd_fixed_splitted_cell = None
                cmd_fixed_splitted_cell_length = None
                cmd_fixed_splitted_cell_index = None

                position = None

                try:
                    cmd_fixed = cmd.split(';')[0].replace(',', ' ')

                    if cmd_fixed is not None:
                        cmd_fixed_length = len(cmd_fixed)

                        if cmd_fixed_length > 0:
                            cmd_fixed_splitted = filter(None, cmd_fixed.split(' '))

                            if cmd_fixed_splitted is not None:
                                cmd_fixed_splitted_amount = len(cmd_fixed_splitted)

                                if cmd_fixed_splitted_amount > 0:
                                    cmd_fixed_splitted_index = cmd_fixed_splitted_amount - 1

                                    while cmd_fixed_splitted_index >= 1:
                                        # 1 because the first 2 are always a command and either a type or a variable (register)
                                        # , and we don't need to check the command cell

                                        cmd_fixed_splitted_cell = cmd_fixed_splitted[cmd_fixed_splitted_index]
                                        cmd_fixed_splitted_cell_length = len(cmd_fixed_splitted_cell)

                                        position = cmd_fixed_splitted_index + 1

                                        if cmd_fixed_splitted_cell_length > 0:
                                            check_entitlement_result = check_entitlement()

                                            if check_entitlement_result == 1:
                                                method_found = True
                                            elif check_entitlement_result == -1:
                                                error_found = True

                                            if method_found is True:
                                                method_found = False

                                                break
                                            elif error_found is True:
                                                error_found = False

                                                raise Exception(None)

                                        cmd_fixed_splitted_index -= 1
                except Exception:
                    error_message = []

                    error_message.append("can't parse.")

                    if failure_text is not None:
                        error_message.append("reason:" + ' ' + failure_text)

                    error_message.append("address:" + ' ' + CheckHexText(current_head, AddressesLength, True))

                    if cmd_fixed_splitted is not None:
                        error_message.append("command:" + ' ' + '\t'.join(cmd_fixed_splitted))

                    if position is not None:
                        error_message.append("position:" + ' ' + str(position) + ' ' + "out of:" + ' ' + str(cmd_fixed_splitted_amount))

                    if CreateSequence(current_head, None) is True:
                        SequenceBytesText = CheckSequenceBytesText(True)

                        if SequenceBytesText is not None:
                            error_message.append("sequence bytes:" + ' ' + SequenceBytesText)

                    print('\t'.join(error_message))

                    failures += 1

    print("")
    print("finished parsing addresses between first segment to the segment before the memory hole")

    # going through all of the addresses from segment before mem hole virtual address
    # to the segment after the mem hole mapped virtual address + its file size (not including the last one since it's an address of the next segment)

    # print("")
    # print("parsing addresses between the segment before the memory hole to the segment after the memory hole and its file size")

    # print("")
    # print("finished parsing addresses between the segment before the memory hole to the segment after the memory hole and its file size")


def main():
    # Global Variables

    global verbose
    global sound

    global FirstSegment_VirtualAddress

    global SecondSegment_VirtualAddress

    global EntitlementLength

    global BytesLength
    global SizesLength
    global AddressesLength

    global successes
    # global success_text

    global failures
    # global failure_text

    # global heads
    # global heads_amount
    # global heads_index
    # global previous_head
    # global current_head
    # global next_head

    # global cmd
    # global cmd_length
    # global cmd_fixed
    # global cmd_fixed_length
    # global cmd_fixed_splitted
    # global cmd_fixed_splitted_amount
    # global cmd_fixed_splitted_index
    # global cmd_fixed_splitted_cell
    # global cmd_fixed_splitted_cell_length
    # global cmd_fixed_splitted_cell_index

    # global position

    # global entitlement_bytes_amount

    # global entitlement_allowed_characters
    global entitlement_allowed_characters_matches

    # global suggested_entitlement_allowed_characters
    global suggested_entitlement_allowed_characters_matches

    global suggested_hardcore_entitlement_allowed_characters_matches

    # global sequence_bytes
    # global sequence_bytes_address
    # global sequence_bytes_original_amount
    # global sequence_bytes_amount
    # global sequence_bytes_offset
    # global sequence_bytes_index
    # global sequence_byte

    # Function Variables

    start_time = None
    end_time = None

    elapsedTime = None

    elapsedMinutes = None
    elapsedSeconds = None

    # Start

    # WaitForInitialAutoanalysis()

    start_time = datetime.now().time().strftime('%H:%M:%S')

    print("")
    print("User Input:")
    print(
        "Verbose:" + ' ' + ("True" if verbose is True else "False") + "\n"
        + "First Segment Virtual Address:" + ' ' + CheckHexText(FirstSegment_VirtualAddress, AddressesLength, True) + "\n"
        + "Second Segment Virtual Address:" + ' ' + CheckHexText(SecondSegment_VirtualAddress, AddressesLength, True)
    )

    print("")
    print("Program Input:")
    print(
        "Entitlement Length:" + ' ' + str(EntitlementLength)
    )

    fix_addresses()

    end_time = datetime.now().time().strftime('%H:%M:%S')

    elapsedTime = datetime.strptime(end_time, '%H:%M:%S') - datetime.strptime(start_time, '%H:%M:%S')

    elapsedMinutes = int(elapsedTime.total_seconds() / 60)
    elapsedSeconds = int(elapsedTime.total_seconds() - elapsedMinutes * 60)

    print("")
    print("successes:" + ' ' + str(successes))
    print("failures:" + ' ' + str(failures))

    print("")
    print("matches between first segment to the second segment:")
    print("entitlement allowed characters matches:" + ' ' + str(entitlement_allowed_characters_matches))
    print("suggested entitlement allowed characters matches:" + ' ' + str(suggested_entitlement_allowed_characters_matches))
    print("suggested hardcore entitlement allowed characters matches:" + ' ' + str(suggested_hardcore_entitlement_allowed_characters_matches))

    print("")
    print("elapsed time:" + ' ' + str(elapsedMinutes).zfill(2) + ':' + str(elapsedSeconds).zfill(2))

    if sound is True:
        CompletionSound()

    print("")
    print("done")


main()
