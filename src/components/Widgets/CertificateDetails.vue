<template>
<div class="certificates-content">
  <!-- host cards container -->
  <div class="host-cards" :style="`height: ${listSize * 3 + 3}em`">
    <!-- open card modal overlay -->
    <div @click="closeCard" class="overlay"></div>
    <!-- host cards list -->
    <div v-for="(certificate, idx) in certificates" :key="idx" class="host-card"
         :style="`top: ${(idx * 3 + 0.5)}em`" @click="openCard"
         :data-num-certs="certificate.certsInChain" :data-has-error="!!certificate.error">
      <!-- closed card - host status summary -->
      <div :class="`summary ${summaryClass(certificate.status)}`">
        {{ summaryText(certificate.status) }}
        <span>{{ daysLeftText(certificate.status) }}</span>
      </div>
      <!-- open card - action buttons -->
      <div class="actions">
        <i v-if="certificate.info" class="far fa-info-circle small info-icon"
           v-tooltip="certificate.info"></i>
        <a i v-if="certificate.url" :href="certificate.url" target="_blank">
          <i class="far fa-external-link small"
           v-tooltip="`Open ${certificate.url} in new tab`"></i>
        </a>
        <i @click="retrieveCertificate(certificate.host, certificate.port)"
            class="far fa-redo small" v-tooltip="'Reload certificate details from host'"></i>
        <i v-if="!!certificate.fingerprints.sha1"
           @click="toggleFingerprints" class="far fa-fingerprint small fingerprint"
           v-tooltip="'View certificate fingerprints'"></i>
        <i v-if="certificate.certsInChain > 1"
           @click="toggleChain" class="far fa-link small chain"
           v-tooltip="'View certificate chain'"></i>
        <i v-if="!!certificate.error" @click="toggleError"
           :class="`far fa-exclamation-circle small error status-${certificate.status.text}`"
           v-tooltip="'View error information'"></i>
        <i @click="closeCard" class="far fa-times-circle small" v-tooltip="'Close'"></i>
      </div>
      <!-- closed card - host:port -->
      <p class="host-summary textover">
        <i :class="`fal fa-${statusIcon(certificate.status.text)}
                    status-icon status-${certificate.status.text.toLowerCase()}`"
        ></i>
        <span class="certificate-host" v-tooltip="`${certificate.host}:${certificate.port}`">
          {{ certificate.host }}
        </span>
        <span v-if="certificate.port != 443" class="certificate-port">
          :{{ certificate.port }}
        </span>
      </p>
      <!-- open card - main info section -->
      <div class="certificate-details">
        <p class="address textover" v-tooltip="`${certificate.host} port ${certificate.port}`">
            <code :class="hostClass(certificate.host)">{{ certificate.host }}</code>
            <span class="port">port </span><code>{{ certificate.port }}</code>
        </p>
        <p class="certificate-status">
          <i v-if="statusWarning(certificate.status) && statusNotError(certificate.status)"
             :class="`far fa-exclamation-triangle ${summaryClass(certificate.status)}`"></i>
          <span :class="`status status-${certificate.status.text.toLowerCase()}`">
            <strong>{{ statusText(certificate.status) }}</strong>
          </span>
          <span v-if="!statusWarning(certificate.status)">
            <span v-if="!!daysText(certificate.status.daysLeft)" class="days-days">
              <strong>{{ Math.abs(certificate.status.daysLeft) }}</strong>
            </span>
            <span :class="`days-text status-${certificate.status.text}`">
              {{ daysText(certificate.status.daysLeft) }}
            </span>
          </span>
          <span v-else-if="statusNotError(certificate.status)"
                :class="summaryClass(certificate.status)">
            {{ summaryText(certificate.status) }}
          </span>
        </p>
      </div>
      <!-- open card - main certificate details / certificate chain -->
      <div class="certificate-chain">
        <div v-for="(cert, cidx) in certificate.certificates" :key="cidx" class="certificate-wrap">
          <div :class="`certificate ${cidx > 0 ? 'sub' : 'main'}-certificate`">
            <div class="issuer textover">
              <label>Issued By</label>
              <strong class="org textover" v-tooltip="`${cert.issuer.org} (${cert.issuer.cn})`">
                <i v-if="unknownIssuer(cert.issuer)" class="fal fa-exclamation-triangle"></i>
                {{ issuerOrg(cert.issuer) }}
              </strong>
              <span v-if="!!cert.issuer.cn" class="cn textover" v-tooltip="cert.issuer.cn">
                ({{ cert.issuer.cn }})
              </span>
            </div>
            <div v-if="cidx > 0" class="subject textover">
              <label>Subject</label>
              <strong v-if="cert.subject.org" class="org textover"
                      v-tooltip="`${cert.subject.org} (${cert.subject.cn})`">
                {{ cert.subject.org }}
              </strong>
              <span class="cn textover" v-tooltip="cert.subject.cn">({{ cert.subject.cn }})</span>
            </div>
            <div class="valid-until">
              <label>Valid Until</label>
              <strong>{{ cert.validTo }}</strong>
            </div>
            <div class="valid-from">
              <label>Valid From</label>
              <strong>{{ cert.validFrom }}</strong>
            </div>
          </div>
          <div class="cert-sep">&nbsp;</div>
        </div>
      </div>
      <!-- open card - error view -->
      <div class="host-error" v-if="!!certificate.error">
        <p v-if="certificate.error.message">{{ certificate.error.message }}</p>
        <p v-if="certificate.error.reason" class="reason">Reason: {{ certificate.error.reason }}</p>
        <p v-if="!!certificate.error.verify" class="verify">
          <code v-tooltip="`OpenSSL verify return code: ${certificate.error.verify.code}`"
                :class="verifyCodeClass(certificate.error.verify)"
                >{{ certificate.error.verify.message }}</code>
          <a href="https://www.openssl.org/docs/man1.1.1/man1/verify.html" target="_blank"
             v-tooltip="'Open OpenSSL verify man page in new tab'">
            <i class="far fa-question-circle"></i>
          </a>
        </p>
      </div>
      <!-- open card - certificate fingerprints view -->
      <div class="fingerprints">
        <p v-if="certificate.fingerprints.sha1">
          <label>SHA1</label><code>{{ certificate.fingerprints.sha1 }}</code>
        </p>
        <p v-if="certificate.fingerprints.sha256">
          <label>SHA256</label><code>{{ certificate.fingerprints.sha256 }}</code>
        </p>
      </div>
      <!-- open card - footer -->
      <div class="card-footer">
        <span v-if="certificate.status.lastUpdated > 0" class="last-updated">
          Updated {{ new Date(certificate.status.lastUpdated).toLocaleString() }}
        </span>
        <span v-if="certificate.certsInChain > 1" class="more-certificates" @click="toggleChain">
          {{ certificate.certsInChain - 1 }} more in certificate chain
          <i class="far fa-chevron-circle-up"></i>
        </span>
      </div>
    </div>
  </div>
</div>
</template>
<script>
import axios from 'axios';
import WidgetMixin from '@/mixins/WidgetMixin';

const defaults = {
  listSize: {
    vendor: 8,
    min: 7,
    max: 500,
  },
  warnDaysBeforeExpiry: 21,
  alertDaysBeforeExpiry: 14,
};

/**
 * CertificateDetails widget - Displays validity period, issuer and subject details,
 * fingerprints and verification errors of publicly available SSL/TLS certificates
 * (e.g. website or mail server).
 */
export default {
  mixins: [WidgetMixin],
  data() {
    return {
      certificates: null,
    };
  },
  computed: {
    /* Parse the user provided hosts lists */
    hosts() {
      const hosts = [];
      if (!this.options.hosts || !Array.isArray(this.options.hosts)) return [];
      this.options.hosts.forEach(entry => {
        const [host0, info, url] = entry.split(',');
        const [host, port0] = host0.split(':');
        const port = parseInt(port0, 10) || 443;
        const fingerprints = {};
        const status = {
          code: -9,
          text: 'Loading',
        };
        hosts.push({
          host, port, info, url, status, fingerprints,
        });
      });
      return hosts;
    },
    /* Build URL query string for hosts lists */
    hostsQuery() {
      return this.hosts.map(entry => `hosts=${entry.host}:${entry.port}`).join('&');
    },
    /* Calculate host cards list size taking into account 'listSice' user option */
    listSize() {
      const { vendor, min, max } = defaults.listSize;
      const max0 = Math.min(max, this.hosts.length + 3);
      if (this.options.listSize === 'all') return max0;
      return Math.min(max0, Math.max(min, parseInt(this.options.listSize, 10) || vendor));
    },
    /* Sort by expiry date user option */
    sortByExpiry() {
      return !!this.options.sortByExpiry;
    },
    /* Expiry threshold in days */
    warnDaysBeforeExpiry() {
      return parseInt(this.options.warnDaysBeforeExpiry, 10) || 21;
    },
    alertDaysBeforeExpiry() {
      return parseInt(this.options.alertDaysBeforeExpiry, 10) || 14;
    },
  },
  methods: {
    fetchData() {
      this.retrieveCertificates();
    },
    /* Merge user provied optional host information (info, url) with backend response */
    updateHost(newHosts) {
      return newHosts.map(entry => {
        const e = entry;
        const h = this.hosts.filter(host => host.host === entry.host && host.port === entry.port);
        if (h.length === 1) {
          e.info = h[0].info;
          e.url = h[0].url;
        }
        e.certsInChain = entry.certificates?.length || 0;
        e.fingerprints = {};
        if (e.certsInChain) e.fingerprints = entry.certificates[0].fingerprints;
        return e;
      });
    },
    /* Call the fetch-certificate backend endpoint for w/ single host */
    retrieveCertificate(host, port) {
      const baseUrl = process.env.VUE_APP_DOMAIN || window.location.origin;
      const endpoint = `${baseUrl}/fetch-certificate/?&host=${host}&port=${port}`;
      axios.get(endpoint)
        .then(response => {
          if (!response.data) return;
          const newHosts = [];
          this.certificates.forEach(entry => {
            if (entry.host === host && entry.port === port) newHosts.push(response.data);
            else newHosts.push(entry);
          });
          if (newHosts.length) this.certificates = this.updateHost(newHosts);
        })
        .catch(err => this.error('ERROR retrieving certificate', err));
    },
    /* Call the fetch-certificates backend endpoint w/ all hosts */
    retrieveCertificates() {
      const baseUrl = process.env.VUE_APP_DOMAIN || window.location.origin;
      const endpoint = `${baseUrl}/fetch-certificates/?&${this.hostsQuery}`;
      axios.get(endpoint)
        .then(response => {
          if (!response.data) return;
          const certs = this.updateHost(response.data);
          this.certificates = this.sortByExpiry
            ? certs.sort((a, b) => parseFloat(a.status.daysLeft)
                                 - parseFloat(b.status.daysLeft))
            : certs;
        })
        .catch(err => this.error('ERROR retrieving certificates', err));
    },
    /* Helper function to return HTML elements of card-layout UI */
    cardsUI(event) {
      const overlay = this.$el.querySelector('.host-cards .overlay');
      let { target } = event;
      // find clicked card
      while (target.parentNode && !target.classList.contains('host-card')) {
        target = target.parentNode;
      }
      // find open card (when overlay is clicked)
      if (target instanceof Document) {
        target = this.$el.querySelector('.host-card.selected');
      }
      const selected = target.classList.contains('selected');
      const numCerts = parseInt(target.getAttribute('data-num-certs'), 10) || 0;
      const hasError = target.getAttribute('data-has-error');
      return {
        overlay, target, selected, numCerts, hasError,
      };
    },
    /* Open and close individual host card */
    openCard(event) {
      const {
        overlay, target, selected, numCerts, hasError,
      } = this.cardsUI(event);
      if (selected) return;
      overlay.style.display = 'block';
      target.classList.add('selected');
      if (numCerts === 0 || hasError) this.openError(event);
    },
    closeCard(event) {
      event.stopPropagation();
      const {
        overlay, target,
      } = this.cardsUI(event);
      if (target.classList.contains('chain-view')) this.closeChain(event);
      if (target.classList.contains('fingerprint-view')) this.closeFingerprints(event);
      if (target.classList.contains('error-view')) this.closeError(event);
      overlay.style.display = 'none';
      target.classList.remove('selected');
    },
    /* Open and close various views within open host card */
    toggleChain(event) {
      const { target } = this.cardsUI(event);
      const open = target.classList.contains('chain-view');
      if (open) this.closeChain(event);
      else this.openChain(event);
    },
    openChain(event) {
      const { target } = this.cardsUI(event);
      this.closeFingerprints(event);
      this.closeError(event);
      target.classList.add('chain-view');
    },
    closeChain(event) {
      const { target } = this.cardsUI(event);
      target.classList.remove('chain-view');
    },
    toggleFingerprints(event) {
      const { target } = this.cardsUI(event);
      const open = target.classList.contains('fingerprint-view');
      if (open) this.closeFingerprints(event);
      else this.openFingerprints(event);
    },
    openFingerprints(event) {
      const { target } = this.cardsUI(event);
      this.closeChain(event);
      this.closeError(event);
      target.classList.add('fingerprint-view');
    },
    closeFingerprints(event) {
      const { target } = this.cardsUI(event);
      target.classList.remove('fingerprint-view');
    },
    toggleError(event) {
      const { target } = this.cardsUI(event);
      const open = target.classList.contains('error-view');
      if (open) this.closeError(event);
      else this.openError(event);
    },
    openError(event) {
      const { target } = this.cardsUI(event);
      this.closeChain(event);
      this.closeFingerprints(event);
      target.classList.add('error-view');
    },
    closeError(event) {
      const { target } = this.cardsUI(event);
      target.classList.remove('error-view');
    },
    /* Helper function to handle reactive components based on state of data */
    summaryText(status) {
      switch (status.code) {
        case 0:
          if (status.daysLeft < this.warnDaysBeforeExpiry) {
            return `Expires in ${status.daysLeft} day${status.daysLeft > 1 ? 's' : ''}`;
          }
          return status.text.toUpperCase();
        case -9:
          return status.text;
        default:
          return status.text.toUpperCase();
      }
    },
    summaryClass(status) {
      switch (status.code) {
        case 0:
          if (status.daysLeft <= this.alertDaysBeforeExpiry) return 'alert status-expired';
          if (status.daysLeft <= this.warnDaysBeforeExpiry) return 'warning status-error';
          return `status-${status.text.toLowerCase()}`;
        default:
          return `status-${status.text.toLowerCase()}`;
      }
    },
    hostClass(hostname) {
      const l = hostname.length;
      let extra;
      if (l > 32) extra = 'smaller';
      else if (l > 26) extra = 'small';
      else extra = '';
      return `host ${extra}`;
    },
    statusText(status) {
      const text = status.text.toLowerCase();
      const code = status.code || 0;
      switch (text) {
        case 'ok':
          return 'Certificate is VALID';
        case 'expired':
          return 'Certificate EXPIRED';
        case 'invalid':
          return 'Certificate NOT VALID for host';
        case 'error':
          switch (code) {
            case 1:
              return 'Connection ERROR';
            case 11: default:
              return 'Certificate VERIFY FAILED';
          }
        default:
          return '';
      }
    },
    statusIcon(statusText) {
      switch (statusText.toLowerCase()) {
        case 'ok': case 'loading': default:
          return 'file-certificate';
        case 'expired':
          return 'calendar-exclamation';
        case 'error': case 'invalid':
          return 'exclamation-square';
      }
    },
    statusWarning(status) {
      const text = status.text.toLowerCase();
      const error = text === 'error' || text === 'invalid';
      if (!error && status.daysLeft > 0 && status.daysLeft < this.warnDaysBeforeExpiry) return true;
      return error;
    },
    statusNotError(status) {
      const text = status.text.toLowerCase();
      return text !== 'error' && text !== 'invalid';
    },
    daysText(days) {
      if (typeof days !== 'number') return '';
      if (days < 0) return 'days ago';
      return 'days left';
    },
    daysLeftText(status) {
      if (status.code !== 0 || Math.abs(status.daysLeft) < this.warnDaysBeforeExpiry) return '';
      return `${status.daysLeft}d`;
    },
    issuerOrg(issuer) {
      if (!issuer.org && !issuer.cn) return 'Unknown';
      return issuer.org;
    },
    unknownIssuer(issuer) {
      return !issuer.org && !issuer.cn;
    },
    verifyCodeClass(verify) {
      const l = verify.message.length;
      if (l > 45) return 'smaller';
      if (l > 40) return 'small';
      return '';
    },
  },
  created() {
    this.certificates = this.hosts;
    this.overrideUpdateInterval = 60 * 60 * 24;
  },
};
</script>

<style scoped lang="scss">
@import '@/styles/style-helpers.scss';

/* main container */
.certificates-content {
  margin-right: -1em;
  margin-left: -1em;
  margin-top: .75em;
  /* cards list scrollpane */
  .host-cards {
    position: relative;
    display: block;
    height: 24em;
    margin: 0 0 .25em 0;
    overflow-x: hidden;
    overflow-y: auto;
    @extend .scroll-bar;
    /* modal overlay */
    .overlay {
      position: sticky;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: var(--background);
      opacity: .66;
      z-index: 1;
      display: none;
    }
  }
  /* individual card */
  .host-card {
    position: absolute;
    top: 0;
    border: .15em solid var(--primary);
    border-radius: 1em .5em .5em .5em;
    width: 80%;
    min-height: 14em;
    background: var(--widget-background-color);
    margin: 0 7.5%;
    color: var(--widget-text-color);
    padding: 0 .5em;
    cursor: pointer;

    > p {
      margin: .75em 0 .5em 0;
      font-weight: bold;
      font-size: 1.1em;
      > i {
        vertical-align: text-top;
      }
    }
    .certificate-wrap:not(:first-child) {
      display: none;
    }
    .textover {
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    /* card header */
    .status {
      font-size: 1.2em;
      width: .85em;
      text-align: center;
    }
    .status-unknown {
      color: var(--medium-grey);
      opacity: .66;
    }
    .status-loading {
      color: var(--medium-grey);
      opacity: .66;
    }
    .status-ok {
      color: var(--success);
    }
    .status-error, .status-invalid {
      color: var(--error);
    }
    .status-expired {
      color: var(--danger);
    }
    .status-icon {
      font-size: 1.25em;
      width: 1.1em;
      text-align: center;
    }
    .certificate-port {
      font-size: .8em;
      opacity: .66;
    }
    .summary {
      float: right;
      margin: .9em 0 .65em .5em;
      span {
        font-size: .9em;
      }
    }
    .summary.warning, .summary.alert {
      padding: .2em .5em;
      margin-top: .55em;
      border-radius: .33em;
      font-weight: bold;
      border: .1em solid;
    }
    /* card header - buttons */
    .actions {
      float: right;
      margin: .25em 0 .75em 0;
      display: none;
      i {
        font-size: 1.25em;
        padding: .25em;
        min-width: .85em;
        text-align: center;
        border-top: .15em solid transparent;
        opacity: .66;
      }
      i:not(.info-icon) {
        cursor: pointer;
      }
      i:hover {
        border-top: .15em solid var(--widget-text-color);
        opacity: 1;
      }
      a {
        color: unset;
      }
    }
    /* expiry warning in certificate status section */
    .certificate-status {
      i {
        font-size: 1.2em;
        margin-right: .5em;
      }
      span.warning {
        margin-left: .25em;
      }
    }
    /* certificate fingerprints section */
    .fingerprints {
      position: absolute;
      top: 4em;
      display: none;
      line-break: anywhere;
      line-height: 1.66em;
      margin: 1.85em .5em 0 0;
      font-weight: bold;
      label {
        font-size: .9em;
        margin-right: .25em;
        font-weight: normal;
        opacity: .66;
      }
      p {
        font-size: .95em;
        code {
          opacity: .85;
        }
      }
      p:first-child {
        margin: 1.75em 0 .5em 0;
      }
      p:last-child {
        margin: .5em 0 0 0;
      }
    }
    /* certificate status section - default view when no error */
    .certificate-details {
      text-align: center;
      p:first-child {
        margin: .75em 0 0 0;
        min-width: 80%;
      }
      p:nth-child(2) {
        margin: 1em 0;
      }
      .address {
        background: var(--widget-accent-color);
        display: inline-block;
        max-width: 95%;
        padding: .66em;
        border-radius: .9em;
      }
      .host {
        font-size: 1.1em;
      }
      .host.small {
        font-size: 1em;
      }
      .host.smaller {
        font-size: .9em;
      }
      .port {
        margin-left: .5em;
        opacity: .5;
      }
      .days-days {
        margin-left: .5em;
        font-size: 1em;
      }
      .days-text {
        margin-left: .25em;
        font-size: .9em;
      }
    }
    /* certificate chain section */
    .certificate-chain {
      .main-certificate {
        .subject {
          display: none;
        }
      }
      .sub-certificate {
        display: none;
        .issuer {
          clear: both;
        }
      }
      .certificate {
        > div:not(:first-child) {
          margin-top: 1em;
        }
      }
      label {
        font-size: 1.05em;
        font-weight: bold;
        margin-left: .5em;
        opacity: .75;
      }
      strong {
        font-size: .95em;
        margin-left: .5em;
      }
      span {
        margin-left: .5em;
      }
      .issuer, .subject {
        strong, span {
          text-shadow: .1em .1em .5em rgb(0 0 0 / 80%);
        }
        .org i {
          font-size: .9em;
          color: var(--error);
        }
      }
      .valid-until {
        float: right;
      }
      .valid-from {
        float: left;
      }
      .valid-from, .valid-until {
        display: none;
        strong {
          display: block;
          text-shadow: .1em .1em .5em rgb(0 0 0 / 80%);
        }
        label {
          margin-bottom: .33em;
          display: inline-block;
        }
      }
    }
    /* error section */
    .host-error {
      text-align: center;
      margin-top: 1em;
      display: none;
      .reason, .verify {
        display: none;
      }
      p:first-child {
        font-size: 1.1em;
      }
      p:nth-child(2) {
        opacity: .75;
      }
      p:last-child {
        code {
          opacity: .88;
          background: rgba(0, 0, 0, .33);
          padding: .35em;
          font-size: .9em;
        }
        code.small {
          font-size: .8em;
        }
        code.smaller {
          font-size: .75em;
        }
      }
      a {
        position: relative;
        top: .05em;
        margin-right: -1.5em;
        color: unset;
        i {
          font-size: .9em;
          opacity: .25;
        }
        i:hover {
          opacity: .5;
        }
      }
    }
    /* card footer */
    .card-footer {
      position: absolute;
      bottom: .66em;
      width: 97%;
      i {
        font-size: 1.15em;
        vertical-align: middle;
      }
      .last-updated {
        opacity: .33;
        font-size: .8em;
        display: none;
      }
      .last-updated:hover {
        opacity: .8;
      }
      .more-certificates {
        position: absolute;
        right: 0;
        bottom: -0.2em;
        font-size: .85em;
        opacity: .75;
        cursor: pointer;
      }
      .more-certificates:hover {
        opacity: .9;
      }
    }
  }
  /* open host card (modal) */
  .host-card.selected {
    z-index: 2;
    top: 3em;
    margin: auto;
    min-height: 18em;
    left: 0;
    right: 0;
    width: auto;
    box-shadow: 0 0 4em -2em;
    cursor: default;

    .summary, .certificate-host, .certificate-port, .certificate-wrap:not(:first-child) {
      display: none;
    }
    .actions, .valid-from, .valid-until, .last-updated {
      display: block;
    }
    .certificate-chain .certificate-wrap, .fingerprints p {
      background: rgba(0, 0, 0, .25);
      border-radius: .4em;
      box-shadow: 0 0 .15em 0;
    }
    .certificate-chain .certificate-wrap {
      padding: .5em .5em .01em 0;
    }
    .fingerprints p {
      padding: .33em .33em .2em .5em;
    }
    .certificate-wrap:first-child {
      padding-bottom: .2em;
    }
    .certificate-details {
      p:first-child {
        margin: 0
      }
    }
  }
  .host-card.selected.chain-view .certificate-chain {
    font-size: .95em;
  }
  .host-card.selected.error-view .host-error {
    .reason, .verify {
      display: block;
    }
  }
  /* certificate chain view within open card */
  .host-card.chain-view {
    .certificate-details, .main-certificate, .host-error , .card-footer {
      display: none;
    }
    .sub-certificate, .certificate-wrap:not(:first-child) {
      display: block;
    }
    .certificate-wrap:first-child {
      display: none;
    }
    .actions .chain {
      opacity: 1;
    }
    .certificate-chain .certificate-wrap {
      padding: .5em .5em 0 0;
    }

    .certificate {
      > div:not(:first-child) {
        margin-top: .8em;
      }
    }
    .valid-from, .valid-until {
      margin-bottom: .75em;
    }
  }
  .host-card.chain-view, .host-card.selected {
    div.cert-sep {
      clear: both;
      margin: 0 0 .5em 0;
      line-height: 0;
    }
  }
  /* certificate fingerprints view within open card */
  .host-card.fingerprint-view {
    .certificate-status, .certificate-chain, .host-error, .card-footer {
      display: none;
    }
    .fingerprints {
      display: block;
    }
    .actions .fingerprint {
      opacity: 1;
    }
  }
  /* certificate error view within open card */
  .host-card.error-view {
    .certificate-chain, .fingerprints, .more-certificates {
      display: none;
    }
    .host-error {
      display: block;
    }
    .actions .error {
      opacity: 1;
    }
  }
}
/* theme overrides */
html[data-theme=cherry-blossom], html[data-theme=vaporware] {
  .certificates-content .host-cards .host-card.selected {
    left: .3em;
    right: .3em;
  }
}
</style>
