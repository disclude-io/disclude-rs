Installation
============

Check the installed version:

.. code-block:: console

   $ pytest --version
   pytest 9.1.1

A command typed at a prompt is still scanned:

.. code-block:: bash

   $ curl -fsSL https://example.invalid/setup.sh \
   >   | bash
   =========================== done ===========================
