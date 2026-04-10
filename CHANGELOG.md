# Changelog

All notable changes to EST (Email Spoofing Tool) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Planned: OAuth2 authentication support for modern mail servers
- Planned: Advanced template system for custom scenarios
- Planned: Web-based dashboard for test management
- Planned: Integration with popular penetration testing frameworks

### Changed
- Planned: Improved error handling and user feedback
- Planned: Enhanced logging with structured output

## [3.0.0] - 2026-04-10

### Added
- **File Attachments** - Attach PDF, HTML, or any file type to spoofed emails (`--attachment`)
- **HTML Email Body** - Send raw HTML as the email body (`--html-body`) or load from a file (`--body-file`)
- **Reply-To Header** - Set a custom Reply-To address to redirect replies (`--reply-to`)
- **Email Threading** - Inject emails into existing conversation threads (`--in-reply-to`, `--references`)
- **Bulk / Multi-Target Sending** - Comma-separated targets or load from a file (`--target-list`)
- **Send Throttling** - Configurable delay between sends for bulk campaigns (`--delay`)
- **DNS Validation** - Automatic SPF, DKIM, and DMARC checking before sending for deliverability assessment
- **`dns-check` CLI command** - Standalone DNS record validation from the command line
- **`bulk` CLI command** - Dedicated bulk send mode with scenario or custom options
- **Unified email builder** - Single `_build_email_message()` method handles all message construction
- **DNSValidator class** - Reusable DNS validation with detailed reporting

### Changed
- **Author updated** from "Tech Sky - SRT" to "paris"
- **Version bumped** to 3.0.0
- `test` and `custom` commands now support all new features (attachments, HTML, reply-to, threading, bulk targets, throttling, DNS validation)
- Target argument in `test` command is now optional (can use `--target-list` instead)
- Banner dynamically formats author/license fields

### Removed
- Legacy `_create_mime_email`, `_create_custom_mime_email`, `_create_simple_email`, `_create_simple_custom_email` methods replaced by unified builder

## [2.0.0] - 2025-06-12

### Added
- **Complete rewrite** of EST for professional security testing
- **Multi-threaded SMTP server** with real-time email relay capabilities
- **5 realistic attack scenarios** covering major threat vectors:
  - CEO Fraud / Business Email Compromise
  - IT Helpdesk credential harvesting
  - PayPal phishing simulation
  - Microsoft 365 license scams
  - Banking institution impersonation
- **Custom spoofing tests** with full parameter control
- **Professional installation script** supporting multiple Linux distributions
- **Comprehensive audit logging** with JSON output format
- **Assessment report generation** with security recommendations
- **Cross-platform compatibility** (Linux, macOS, Windows)
- **Desktop integration** with application launchers
- **Bash completion** for command-line efficiency
- **Automatic MX record resolution** for real email delivery
- **Professional CLI interface** with colored output and progress indicators
- **User configuration management** with ~/.est/ directory structure
- **Documentation suite** including quickstart and troubleshooting guides

### Security Features
- **Legal disclaimers** prominently displayed in all outputs
- **Test identification** in all generated emails
- **Secure configuration handling** with proper file permissions
- **Input validation** to prevent injection attacks
- **Ethical use reminders** throughout the application

### Technical Improvements
- **Modern Python architecture** using dataclasses and type hints
- **Robust error handling** with graceful degradation
- **Signal handling** for clean server shutdown
- **Connection pooling** for improved performance
- **DNS fallback mechanisms** for reliable email delivery
- **Professional logging** with multiple output levels

### Documentation
- **Comprehensive README** with installation and usage instructions
- **Professional installation guide** with system requirements
- **Security guidelines** and legal considerations
- **Contributing guidelines** for open source development
- **Code of conduct** establishing community standards
- **API documentation** for developers

### Breaking Changes
- **Complete API redesign** - not compatible with v1.x
- **New command structure** - old commands will not work
- **Configuration format changes** - requires reconfiguration
- **Python 3.8+ requirement** - dropped support for older versions

### Migration from v1.x
- Run the new installation script: `./install.sh`
- Review the new configuration format in `~/.est/config.json`
- Update any scripts to use the new command syntax
- See QUICKSTART.md for updated usage examples

## [1.3.0] - 2024-03-15

### Added
- Basic SMTP relay functionality
- Simple configuration file support
- Command-line argument parsing

### Fixed
- Email encoding issues with special characters
- Connection timeout problems

### Deprecated
- Legacy configuration format (removed in v2.0.0)

## [1.2.1] - 2024-02-20

### Fixed
- Critical security vulnerability in email header handling
- Memory leak in SMTP server

### Security
- Fixed potential injection vulnerability in email headers
- Added input sanitization for user-provided data

## [1.2.0] - 2024-01-10

### Added
- Windows support
- Basic logging functionality
- Email template system

### Changed
- Improved error messages
- Updated dependencies

## [1.1.0] - 2023-11-05

### Added
- macOS support
- Basic email scenarios
- Simple installation script

### Fixed
- Port binding issues on some systems
- DNS resolution problems

## [1.0.0] - 2023-08-20

### Added
- Initial release of EST
- Basic email spoofing capabilities
- Simple SMTP server
- Command-line interface
- MIT license

### Security Considerations
- Added legal disclaimers
- Implemented basic usage warnings

---

## Version Support

- **v2.x**: Current stable release with active development
- **v1.x**: Legacy version, security fixes only until 2025-12-31
- **v0.x**: No longer supported

## Upgrade Guidelines

### From v1.x to v2.x
1. **Backup your data**: Export any custom scenarios or configurations
2. **Uninstall v1.x**: Remove old installation completely
3. **Install v2.0**: Use the new installation script
4. **Migrate configuration**: Manually recreate any custom settings
5. **Update scripts**: Rewrite any automation to use new API

### Security Notes
- Always review the security implications when upgrading
- Test thoroughly in a safe environment before production use
- Review the updated legal disclaimers and usage guidelines

## Development Milestones

### Completed
- ✅ Professional CLI interface
- ✅ Multi-threaded SMTP server
- ✅ Comprehensive logging system
- ✅ Assessment reporting
- ✅ Cross-platform support
- ✅ Professional documentation

### In Progress
- 🔄 Web dashboard development
- 🔄 Advanced template engine
- 🔄 Integration testing suite

### Planned
- 📋 OAuth2 authentication support
- 📋 Cloud deployment options
- 📋 Advanced analytics dashboard
- 📋 Integration with security frameworks
- 📋 Mobile app for remote testing

## Community Contributions

Special thanks to our contributors:

### v2.0.0 Contributors
- **Tech Sky - Ethical Hacking - Security Research Team** - Complete rewrite and professional enhancement
- Community feedback from security professionals worldwide
- Open source contributors and maintainers

### Historical Contributors
- **Tech Sky Development Team** - Initial concept and v1.x development
- Beta testers and security researchers - Critical feedback and bug reports
- Cybersecurity community - Scenario development and testing
- Educational institutions - Research and validation support

## Support Information

- **Bug Reports**: Use GitHub Issues
- **Feature Requests**: GitHub Discussions
- **Security Issues**: Email contact@techskyhub.com
- **General Support**: Email contact@techskyhub.com
- **Technical Questions**: Email contact@techskyhub.com
- **Documentation**: See docs/ directory
- **Community**: GitHub Discussions
- **Website**: https://techskyhub.com

## Acknowledgments

### Special Recognition
- **Tech Sky Team** for dedication to ethical security research
- **Cybersecurity educators** who incorporate EST into training programs
- **Penetration testers** who provide real-world feedback
- **Open source community** for continuous improvement suggestions

### Research Partners
- Educational institutions supporting cybersecurity research
- Security conferences and workshops featuring EST demonstrations
- Ethical hacking communities promoting responsible disclosure

## Legal & Compliance

EST is developed and maintained by **Tech Sky - Ethical Hacking - Security Research Team** with a commitment to:

- **Ethical security testing** practices and guidelines
- **Legal compliance** with applicable cybersecurity regulations
- **Responsible disclosure** of security vulnerabilities
- **Educational advancement** in cybersecurity awareness
- **Professional standards** in penetration testing tools

## Contact Information

**Tech Sky - Ethical Hacking - Security Research Team**

- **Primary Contact**: contact@techskyhub.com
- **Security Reports**: contact@techskyhub.com
- **Partnership Inquiries**: contact@techskyhub.com
- **Educational Licensing**: contact@techskyhub.com

For detailed information about any release, see the corresponding GitHub release notes and commit history.

---

*EST v2.0+ - Professional Email Security Assessment Framework*  
*Developed with ❤️ by Tech Sky - Ethical Hacking - Security Research Team*