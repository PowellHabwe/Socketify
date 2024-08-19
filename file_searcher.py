import os
import mmap
import logging
from typing import Optional, Set

# Configure logging
logging.basicConfig(
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.DEBUG
)

class FileSearcher:
    """Handles file searching operations, including loading file content
    and searching for strings.
    """


    def __init__(self, file_path: str, reread_on_query: bool) -> None:
        """
        Initialize the FileSearcher with file path and REREAD_ON_QUERY
        setting.

        Args:
            file_path (str): Path to the file to be searched.
            reread_on_query (bool): Whether to re-read the file on every
            search query.

        Raises:
            FileNotFoundError: If the specified file does not exist.
            PermissionError: If there's no read permission for the file.
            IOError: For other I/O related errors.
        """
        self.file_path = file_path
        self.reread_on_query = reread_on_query
        self.file_content: Set[str] = set()  # Use a set for quick lookups
        self.mmapped_file: Optional[mmap.mmap] = None  # Type annotation

        if not os.path.exists(self.file_path):
            raise FileNotFoundError(f"The file does not exist at: {self.file_path}")
        if not os.access(self.file_path, os.R_OK):
            raise PermissionError(f"No read permission for file: {self.file_path}")

        self.load_file()  # Pre-load file content or set up mmap


    def load_file(self) -> None:
        """
        Load the file content into a memory-mapped file or a set.

        Raises:
            IOError: If there's an error reading the file.
            MemoryError: If there's not enough memory to load the file.
        """
        try:
            if self.reread_on_query:
                with open(self.file_path, 'r') as file:
                    self.mmapped_file = mmap.mmap(
                        file.fileno(), 0, access=mmap.ACCESS_READ
                    )
                logging.debug(f"The file is memory-mapped at: {self.file_path}")
            else:
                with open(self.file_path, 'r') as file:
                    self.file_content = set(line.strip() for line in file)
                logging.debug(f"The file content is loaded into a set from: {self.file_path}")
        except IOError as e:
            logging.error(f"IOError while loading file {self.file_path}: {e}")
            raise
        except MemoryError as e:
            logging.error(f"Not enough memory to load file {self.file_path}: {e}")
            raise


    def search(self, search_string: str) -> str:
        """
        Search for the string in the memory-mapped file or set.

        Args:
            search_string (str): The string to search for.

        Returns:
            str: "STRING EXISTS\n" if the string is found as an exact match, 
            otherwise "STRING NOT FOUND\n".

        Raises:
            ValueError: If the search string is empty.
            IOError: If there's an error reading from the memory-mapped file.
        """
        if not search_string:
            raise ValueError("Search string cannot be empty")

        try:
            if self.reread_on_query:
                if self.mmapped_file is None:
                    self.load_file()
                if self.mmapped_file:
                    search_bytes = search_string.encode()
                    self.mmapped_file.seek(0)  # Reset position to start of file
                    content = self.mmapped_file.read().decode()
                    lines = content.splitlines()
                    if search_string in lines:
                        return "STRING EXISTS\n"
            else:
                if search_string in self.file_content:
                    return "STRING EXISTS\n"
            return "STRING NOT FOUND\n"
        except IOError as e:
            logging.error(f"Error searching in file: {e}")
            raise
        except Exception as e:
            logging.error(f"Unexpected error during search: {e}")
            raise


    def __del__(self):
        """
        Destructor to ensure the memory-mapped file is closed properly.
        """
        if self.mmapped_file:
            try:
                self.mmapped_file.close()
            except Exception as e:
                logging.error(f"Error closing memory-mapped file: {e}")
