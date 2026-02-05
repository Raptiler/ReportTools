# -*- coding: utf-8 -*-

from burp import IBurpExtender, IHttpListener, IContextMenuFactory
from javax.swing import JMenuItem, JOptionPane
from java.util import ArrayList
import java.awt.Toolkit as Toolkit
import java.awt.datatransfer.StringSelection as StringSelection
import time
import threading
import math

class BurpExtender(IBurpExtender, IHttpListener, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("Report Tools")
        self._callbacks.registerHttpListener(self)
        self._callbacks.registerContextMenuFactory(self)

        self.first_request = None
        self.second_request = None

        print("Report tool By: Paweł Zdunek - AFINE Team v1.04")
        print("""
AAAAAAAAAAAAA       FFFFFFFF       IIII        NNN        NN     EEEEEEEEE
A           A      F                I          NN NN      NN     E
A           A      F                I          NN  NN     NN     E
A           A      FFFFF             I         NN   NN    NN     EEEEEEE
AAAAAAAAAAAAA       F                I         NN    NN   NN     E
A           A      F                I          NN     NN  NN     E
A           A      F                I          NN      NN NN     E
A           A      F              IIIIIII      NN        NNN     EEEEEEEEE
# """)

        self.common_headers = [
            "X-Frame-Options", "X-Content-Type-Options", "Strict-Transport-Security",
            "Content-Security-Policy", "Referrer-Policy", "Permissions-Policy", "Cache-Control"
        ]

        self.api_headers = [
            "Content-type", "Cache-Control", "Strict-Transport-Security", "X-Frame-Options"
        ]

        # Chunk size only for MultiSession copy
        self.MULTISESSION_CHUNK_SIZE = 9999

    def createMenuItems(self, invocation):
        self.context = invocation
        menu = ArrayList()

        menu.add(JMenuItem("Generate API Missing Headers", actionPerformed=self.generate_api_missing_headers))
        menu.add(JMenuItem("Generate Missing Headers", actionPerformed=self.generate_common_missing_headers))

        if invocation.getInvocationContext() == invocation.CONTEXT_MESSAGE_EDITOR_REQUEST:
            menu.add(JMenuItem("[MultiSession] Set as first request",
                               actionPerformed=lambda x: self.set_first_request(invocation)))
            menu.add(JMenuItem("[MultiSession] Set as second request",
                               actionPerformed=lambda x: self.set_second_request(invocation)))

        if self.first_request and self.second_request:
            menu.add(JMenuItem("[MultiSession] Execute MultiSession Check",
                               actionPerformed=lambda x: self.execute_multi_session_check()))

        menu.add(JMenuItem("Copy Request/Response",
                           actionPerformed=lambda x: self.copy_request_response(invocation)))

        return menu

    # ---------------- Missing headers reports ----------------

    def generate_common_missing_headers(self, event):
        self.generate_report(self.common_headers)

    def generate_api_missing_headers(self, event):
        self.generate_report(self.api_headers)

    def generate_report(self, headers_to_check):
        http_traffic = self.context.getSelectedMessages()
        if len(http_traffic) == 0:
            return

        message_info = http_traffic[0]
        request_info = self._helpers.analyzeRequest(message_info)
        url = request_info.getUrl().toString()
        request_headers = request_info.getHeaders()
        request_headers_text = "\n".join(request_headers)

        if message_info.getResponse() is None:
            JOptionPane.showMessageDialog(None, "Response not found", "Error", JOptionPane.ERROR_MESSAGE)
            return

        response_info = self._helpers.analyzeResponse(message_info.getResponse())
        response_headers = response_info.getHeaders()
        response_headers_lower = [header.split(":")[0].strip().lower() for header in response_headers]

        missing_headers = [header for header in headers_to_check if header.lower() not in response_headers_lower]

        if missing_headers:
            report = "[target]{}[/target]\n".format(url)
            report += "[headers]" + "\n".join(missing_headers) + "[/headers]\n"
            report += "[request]\n" + request_headers_text + "\n" + "[/request]"
            report += "[response]\n" + "\n".join(response_headers) + "\n\n[...]"
            report += "[/response]\n"
            self.copy_to_clipboard(report)  # normal copy (no chunking)
            JOptionPane.showMessageDialog(None, "Missing headers copied to clipboard.", "Info", JOptionPane.INFORMATION_MESSAGE)
        else:
            JOptionPane.showMessageDialog(None, "No missing headers found.", "Info", JOptionPane.INFORMATION_MESSAGE)

    # ---------------- MultiSession ----------------

    def set_first_request(self, invocation):
        self.first_request = invocation.getSelectedMessages()[0]
        self._callbacks.printOutput("First request set.")

    def set_second_request(self, invocation):
        self.second_request = invocation.getSelectedMessages()[0]
        self._callbacks.printOutput("Second request set.")

    def execute_multi_session_check(self):
        def worker():
            try:
                if not self.first_request or not self.second_request:
                    JOptionPane.showMessageDialog(None, "Set first and second request first.", "Error", JOptionPane.ERROR_MESSAGE)
                    return

                first_cookies, first_auth = self.get_headers(self.first_request)
                second_cookies, second_auth = self.get_headers(self.second_request)

                cookies_differences = self.compare_cookies(first_cookies, second_cookies)
                header_report = ""

                if cookies_differences:
                    header_report += "[token1]\n" + "\n".join(
                        "{key}: {value1}".format(key=k, value1=v[0]) for k, v in cookies_differences.items()
                    ) + "[/token1]\n"
                    header_report += "[token2]\n" + "\n".join(
                        "{key}: {value2}".format(key=k, value2=v[1]) for k, v in cookies_differences.items()
                    ) + "[/token2]\n"

                if first_auth != second_auth:
                    header_report += "[auth_header1]\n{}\n[/auth_header1]\n".format(first_auth)
                    header_report += "[auth_header2]\n{}\n[/auth_header2]\n".format(second_auth)

                first_response = self._callbacks.makeHttpRequest(self.first_request.getHttpService(),
                                                                self.first_request.getRequest())
                time.sleep(1)
                second_response = self._callbacks.makeHttpRequest(self.second_request.getHttpService(),
                                                                 self.second_request.getRequest())
                time.sleep(1)
                final_response = self._callbacks.makeHttpRequest(self.first_request.getHttpService(),
                                                                self.first_request.getRequest())

                clipboard_content = (
                    header_report +
                    "[request1]\n" + self._helpers.bytesToString(self.first_request.getRequest()) + "[/request1]\n\n" +
                    "[response1]\n" + self.process_response(first_response) + "[/response1]\n\n" +
                    "[request2]\n" + self._helpers.bytesToString(self.second_request.getRequest()) + "[/request2]\n\n" +
                    "[response2]\n" + self.process_response(second_response) + "[/response2]\n\n" +
                    "[request3]\n" + self._helpers.bytesToString(self.first_request.getRequest()) + "[/request3]\n\n" +
                    "[response3]\n" + self.process_response(final_response) + "[/response3]"
                )

                # NEW: chunked copy for MultiSession
                self.copy_to_clipboard_chunked(
                    clipboard_content,
                    chunk_size=self.MULTISESSION_CHUNK_SIZE,
                    title="MultiSession Copy"
                )

                self._callbacks.printOutput("MultiSession: chunked copy finished.")
                JOptionPane.showMessageDialog(None, "MultiSession data copied (chunked).", "Info", JOptionPane.INFORMATION_MESSAGE)

                self.first_request = None
                self.second_request = None

            except Exception as e:
                self._callbacks.printError("Error during execution: {}".format(str(e)))
                JOptionPane.showMessageDialog(None, "Error during execution:\n{}".format(str(e)), "Error", JOptionPane.ERROR_MESSAGE)

        thread = threading.Thread(target=worker)
        thread.start()

    def get_headers(self, request_response):
        analyzed_request = self._helpers.analyzeRequest(request_response.getRequest())
        headers = analyzed_request.getHeaders()
        cookies, authorization = {}, None
        for header in headers:
            if header.startswith("Cookie:"):
                cookies.update(self.parse_cookies(header[len("Cookie: "):]))
            elif header.startswith("Authorization:"):
                authorization = header
        return cookies, authorization

    def parse_cookies(self, cookie_header):
        return dict(part.split("=", 1) for part in cookie_header.split("; ") if "=" in part)

    def compare_cookies(self, cookies1, cookies2):
        differences = {}
        for key in cookies1:
            if key in cookies2:
                if cookies1[key] != cookies2[key]:
                    differences[key] = (cookies1[key], cookies2[key])
            else:
                differences[key] = (cookies1[key], None)
        for key in cookies2:
            if key not in cookies1:
                differences[key] = (None, cookies2[key])
        return differences

    def process_response(self, response):
        response_info = self._helpers.analyzeResponse(response.getResponse())
        body_offset = response_info.getBodyOffset()
        body = response.getResponse()[body_offset:]
        return self._helpers.bytesToString(response.getResponse()[:body_offset]) + "[...]" if len(body) > 200 else self._helpers.bytesToString(response.getResponse())

    # ---------------- Copy request/response (normal copy) ----------------

    def copy_request_response(self, invocation):
        try:
            http_traffic = invocation.getSelectedMessages()[0]
            request_info = self._helpers.analyzeRequest(http_traffic)
            url = request_info.getUrl().toString()

            request_headers = request_info.getHeaders()
            request_body = http_traffic.getRequest()[request_info.getBodyOffset():].tostring()

            request = "\n".join(request_headers) + "\n\n" + request_body

            if http_traffic.getResponse():
                response_info = self._helpers.analyzeResponse(http_traffic.getResponse())
                response_headers = response_info.getHeaders()

                formatted_response = "\n".join(response_headers) + "\n\n[...]"
                text_to_copy = "[target]{}[/target][request]\n{}[/request]\n[response]\n{}[/response]".format(url, request, formatted_response)
                JOptionPane.showMessageDialog(None, "Data Copied to clipboard", "Info", JOptionPane.INFORMATION_MESSAGE)
            else:
                raise ValueError("Response not found")

        except Exception as e:
            JOptionPane.showMessageDialog(None, "Response not found", "Error", JOptionPane.ERROR_MESSAGE)
            # fall back, but keep request if possible
            try:
                text_to_copy = "[request]\n{}[/request]".format(request)
            except:
                text_to_copy = "[request]\n(no request)[/request]"

        self.copy_to_clipboard(text_to_copy)  # normal copy (no chunking)

    # ---------------- Clipboard helpers ----------------

    def _format_for_clipboard(self, text):
        """
        Keep existing behavior:
        - remove lines starting with Sec-
        - replace newlines with [br]\n for templates
        """
        lines = text.splitlines()
        filtered_lines = [line for line in lines if not line.strip().startswith("Sec-")]
        filtered_text = ''.join([line.rstrip() + '[br]\n' for line in filtered_lines])
        return filtered_text

    def copy_to_clipboard(self, text):
        """
        Old behavior: copy everything at once.
        Used by: Missing headers + Copy Request/Response
        """
        filtered_text = self._format_for_clipboard(text)
        string_selection = StringSelection(filtered_text)
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(string_selection, None)

    def copy_to_clipboard_chunked(self, text, chunk_size=9999, title="Copy"):
        """
        NEW behavior (MultiSession):
        Copies text in chunks of chunk_size, showing progress dialogs:
        "Skopiowano 1/7" -> OK -> "Skopiowano 2/7" -> ...
        """
        filtered_text = self._format_for_clipboard(text)

        total_len = len(filtered_text)
        if total_len <= chunk_size:
            # single shot still shows 1/1 (consistent UX)
            self._set_clipboard(filtered_text)
            JOptionPane.showMessageDialog(None, u"Skopiowano 1/1", title, JOptionPane.INFORMATION_MESSAGE)
            return

        total_parts = int(math.ceil(float(total_len) / float(chunk_size)))
        part = 1
        pos = 0

        while pos < total_len:
            chunk = filtered_text[pos:pos + chunk_size]
            self._set_clipboard(chunk)
            JOptionPane.showMessageDialog(None, u"Skopiowano {}/{}".format(part, total_parts), title, JOptionPane.INFORMATION_MESSAGE)
            pos += chunk_size
            part += 1

    def _set_clipboard(self, txt):
        string_selection = StringSelection(txt)
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(string_selection, None)

    # ---------------- IHttpListener ----------------

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        pass
