# Snapdump format

The snapsnap dump format is pretty simple and is a simple stream of records.

## Header

| Name         | Type  | Description                                                 |
| :---:        | :---: | :----------:                                                |
| Magic        | u32   | Snapdump magic "SDMP"                                       |
| Architecture | u32   | Magic number representing the architecture used in the dump |
| Entries      | u32   | Number of entries                                           |

### Architectures

| Name    | Value |
| :---:   | :---: |
| x86\_64 | 0     |

## Entries

Every entry has the following format

| Name       | Type     | Description        |
| :---:      | :---:    | :----------:       |
| Entry type | u32      | Type of the entry  |
| Entry data | variable | Entry defined data |

### Memory mapping (type = 0x5050414d)

| Name       | Type     | Description                                                   |
| :---:      | :---:    | :----------:                                                  |
| Protection | u8       | Memory mapping permissions (read = 1, write = 2, execute = 4) |
| Start      | u64      | Mapping start address                                         |
| End        | u64      | Mapping end address                                           |
| Data       | u8       | (end-start) bytes of the mapping data                         |

### Registers (type = 0x53474552)

| Name           | Type     | Description                            |
| :---:          | :---:    | :----------:                           |
| Payload size   | u32      | Size of the register payload           |
| Register state | variable | Implementation specific register state |
