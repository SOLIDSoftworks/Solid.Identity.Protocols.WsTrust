﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Solid.Identity.Protocols.WsTrust.Tests
{
    public static class Certificates
    {
        public const string ValidBase64 = "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";
        public const string InvalidBase64 = "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";
        public const string ExpiredBase64 = "MIIKKQIBAzCCCeUGCSqGSIb3DQEHAaCCCdYEggnSMIIJzjCCBg8GCSqGSIb3DQEHAaCCBgAEggX8MIIF+DCCBfQGCyqGSIb3DQEMCgECoIIE/jCCBPowHAYKKoZIhvcNAQwBAzAOBAibVTCMGjtb6QICB9AEggTYJ11tYDPdXo90FauhB5kGLYRAyT7ludhQb3cPLDtcBxIv/e1doI/1j2dSJDoSy6FIF7GshMzdeoWP/bqw9JW9CQXJMvG3ufwTIvOqg6fQCN9U4n2ZOLHRIPrRW/7YDI6xnBAHYA+Gf3Q9W9fTSN+6VCgTASoBwRaCERWbGxc9eEvZJDx7UaGKlAEX3QXjvQT/YBZ20Uidc/fykHIu6cUj7CI2LQ8pWPn6y1bVcQZ6An0Z/RGLLOS4Z/vlgFIxPkSO73ksRLUboTA3FnuN3b30sdi1Z8gk+2WaOuw2Gb+UgPOC2/uGdlP3UyrEhqE0BpeOP8X0zHZnz0c9uGuw7sXTITgRZSxcB8QV0Av5YhdA8I0vxmgKl2qWELgtIdfzoHUYSnErmW47AOIBfEg6HqGP7QrrZ3GuBZGSQMv5PyIcD2bS21qD2bLjM+1fzFIS2hK64iOfiu3RXlZR6nl1HwaQMWPcLsC6Ckkf24m6qrmXYGJBy69L7ZsXKnMByEVsvQ1Cl5iyxjI1ygTx9NwIV2Hb2JnaLSM4HNxF2mo6bv8cKlc0PPvFV/vOpjKsgAguHFg3HVIdocRt8AwlbHdE9xx/H94IF+7DCE6jVQ6Ec3ydsbMr1JdXzG+f64OdJox9uuQpkCwkIBzA+3W2OvIZavgbRkY6UTWif/1Qv5ipAEs9CBBy3cBGLjqpew7r1TnRV92oRUYogjKTutUPamQXZm1+sFFWXD66A37PsHOSqOS2pkujQJ+wLpEBCzSGC3Mp6VwqvixRXbLaNj7ZHd6fa/kpzKDZuewypy1c7JnWa+xKqr1UEBHRUPYQ8SNtry62sirn6rkfWXQuZ8+CyjVjaFlsHtAGBvvIS67QwLdno4XWE3nrFi11cAjg3bsLVq1GgfaWffxfDnAaczin/769SLMnEzLI5iNqTG9mEsThIjV5T6czyigEcVnboZwAfMw51R6WadAyKuUN3fN6h7omsDde9DIOkSFbP1lS2HjLO6mKeuOJk4bI20/NCnr8UsTl4NLBhiKy7kvsa/2kDOk7cYSpTYAENZiAQ8Zlc0B3ToXt1cHwPyz6FvT/Cg1T3gurbJPEbOFliFI/+1j7XR+kbS7m+uEfZPPwsOB/5wAHKJ+8fBKJLI0jpSha/U3ZkQa90TE8UoMZy+Z63G7IEeyoYfZQh/eRKk/FbBo+lh0x+6AojVhHyT5ZrFnlYNqg2JGwN/qytu/IgI0nSo4zw0bC8i/x0v5uviS7nGX+MFk/LoupSsZHqCleYhCiqPfCeKVMX94F0Yi8vXiMHnPI3DITI72P315wFCuG9f3fQHb7/3LDu67ZWfG4PZNie18u8RGeEL/+VchivmIbdtPjCEjexS7oRi4SK/sVE2yDRwoknndQaiHOYNXJg3XVCyx38H/9CC6fJ/1KNUycj0Wc53wHe4gsPlOsv5OOfBUakhGa7GaPTfrA2nnAZShTZaVqM86O1JG2iS8v0OkSaI/oN0LvVCaXl9DMKx9ogX8xrHkKghe35cp4cWLx7K7av32RHl34bvKtGLK29QAYHOCrPdgO60hXjtjq0VQfQILhNEuMKAYvrqy2LLWyBVNUN13ffc76+ZTSOOwsuIiGI6UgZ1FKULFavdrrV2Mez6zQPHXW94vM2PcpgY70kyXfcDGB4jANBgkrBgEEAYI3EQIxADATBgkqhkiG9w0BCRUxBgQEAQAAADBdBgkqhkiG9w0BCRQxUB5OAHQAZQAtADUAOQA0AGMAOAA3ADQAOQAtAGQAMQA0ADcALQA0ADcAMgA1AC0AYgBkADEAMQAtADYANQBmADAAYgAwADgAMABiAGYAYgBlMF0GCSsGAQQBgjcRATFQHk4ATQBpAGMAcgBvAHMAbwBmAHQAIABTAHQAcgBvAG4AZwAgAEMAcgB5AHAAdABvAGcAcgBhAHAAaABpAGMAIABQAHIAbwB2AGkAZABlAHIwggO3BgkqhkiG9w0BBwagggOoMIIDpAIBADCCA50GCSqGSIb3DQEHATAcBgoqhkiG9w0BDAEDMA4ECFHfYMZz8ifYAgIH0ICCA3CggQrgJinIoK9ESXVjaqHJjj16ApILBodjL6CssKLGIR8QUUQYIG5ZzNGk2jA5iBQ7Jul3Dq/oPas3/zuluJdgaSCTvA159jNbLPtakCTUVhXivRGCF4AGpabo+JUYzb3GoGvd5AXPFVqOe69mSPzIw18A+Tx4kAcF9rSIvSt5bGjSIZuWhYulzqN2JAwBb501Cr0VF0RR8BkZj4ccg5hhsEvPa/dsQP65ENI3NJBJeAvnfhlRET4GFBxuqse7uuWYNsEdHhc1s37+u8UOt8A3dggbZNuGJwdr/GHs8kEj2nE0HZVytSq5ai4ilRPXIkWXiDsJNMfwT4/n+QsHnH8Gqb5LHnwRmvifp9fT7wBS55edcA8Yrj3TghPgi5iDFBmgFRcnN9oXg3Ka0THr3Jp4EMUezzeh3cq/LbmJ3Tpl6ECe6j8dafc1KkBKapOnAUjJBBjSEgNbWo3ZhUNZXMSw7DgVzfxw5/WrpSXnMvVSJyPg3nscjZzA8FYl/ZgooNlTp6ePe0mwhCOMVLcOqVW8f0d8Dka5RBCMFPWDnOo5yJepMNlBJ5w68Qv/QaRCvAxIpGMgCPH73V1GjFeCGTzBGWCqx6n8cgQJy9JHn4rI66f5bxpeUhmcppWMjK/6dr9Mz2ssAv6JHed6dPsuDcyhEOMUgrhwKHQpIDBne8s9BYC8iadg2/lG66AHozyskUKQbnbjQYMNUi2y5WOrRcPNOlsS0Q5Oap2T33sE5BrlgCwO/2qeo5sOtY5pULm2ZJtRTuX10K018eEVplBdP00sC5W9qSxD93r1hIqCYSMvmmdUnajaty2onVlLuDd3twU9dOoWWREYd8SF5frH7n+R2cQhTi0Vh1cmeN9JMRxHalHTeoRxwZPlFC7xA38TBBnZwgEortZiwpayQzp54mY9P4DetKCb29mtlCVEC9UtPrWPr1XbwuOzflOmshegcFHo6IF3p4lLSrrLvqMkCxCUBRIDwl3gnoaEYd86uPgW9pPw7qa7X7FM+ZONtgk6ZzcX6NRmh0tA2sOlb1R92E8Tyo0YRdantBO+YfVJ0vqM8oLQb0eiaRfu3TZ2WByFdeR2GebTohrly64SJKv251f/z5MzsDmajs+MeupNjgS6FJ0EVJRSLUwFa6BtZvnPqKuhYQtpJmPreWhPKRbI933RMDswHzAHBgUrDgMCGgQUHGT+XWaHmGXZG0HjPkDqXQJkTBEEFK+vwtN2oL67lF9DpBi+5z/J7IVwAgIH0A==";
    }
}
