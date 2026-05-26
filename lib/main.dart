// lib/main.dart
import 'dart:convert';
import 'dart:io' show Platform;
import 'package:flutter/foundation.dart' show kIsWeb;
import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'dart:math';

void main() {
  runApp(EmailRiskApp());
}

class EmailRiskApp extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Data Breach Detection',
      theme: ThemeData(primarySwatch: Colors.indigo),
      home: EmailRiskHome(),
      debugShowCheckedModeBanner: false,
    );
  }
}

class EmailRiskHome extends StatefulWidget {
  @override
  _EmailRiskHomeState createState() => _EmailRiskHomeState();
}

class _EmailRiskHomeState extends State<EmailRiskHome> {
  final TextEditingController _controller = TextEditingController();
  bool _loading = false;
  List<dynamic> _results = [];
  List<dynamic> _breaches = [];
  String _error = "";

  // backend base remains editable for optional proxy use; default unused for direct LeakCheck
  String _backendBase = _defaultBackendBase();

  static String _defaultBackendBase() {
    try {
      if (!kIsWeb && Platform.isAndroid) return "http://10.139.117.214:5000"; // common emulator mapping
      return "http://127.0.0.1:5000/";
    } catch (e) {
      return "http://127.0.0.1:5000/";
    }
  }

  void _showSnack(String s) => ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(s)));

  Uri _makeUri(String path) {
    String base = _backendBase;
    if (!base.endsWith("/")) base = "$base/";
    final cleanPath = path.replaceFirst(RegExp(r'^/'), '');
    return Uri.parse(base + cleanPath);
  }

  // ----------------------
  // Local feature extractor (port of your Python)
  // ----------------------
  Map<String, dynamic>? _extractFeatures(String? email) {
    if (email == null) return null;
    final e = email.trim();
    final emailRegex = RegExp(r'^[^@]+@[^@]+\.[^@]+$');
    if (!emailRegex.hasMatch(e)) return null;
    final parts = e.split('@');
    if (parts.length < 2) return null;
    final username = parts[0];
    final domain = parts.sublist(1).join('@');
    if (username.isEmpty) return null;

    final usernameLen = username.length;
    final usernameDigits = username.runes.where((r) => String.fromCharCode(r).contains(RegExp(r'[0-9]'))).length;
    final usernameDots = '.'.allMatches(username).length;
    final usernameUnderscore = '_'.allMatches(username).length;
    final Map<String, int> counts = {};
    for (var ch in username.split('')) {
      counts[ch] = (counts[ch] ?? 0) + 1;
    }
    double entropy = 0.0;
    counts.forEach((k, v) {
      final p = v / usernameLen;
      if (p > 0) entropy -= p * (log(p) / ln2);
    });
    final usernameEntropy = double.parse(entropy.toStringAsFixed(2));
    final domainLen = domain.length;
    final isCommonDomain = (["gmail", "yahoo", "outlook", "hotmail", "protonmail"].any((d) => domain.contains(d))) ? 1 : 0;
    final isEduDomain = (domain.contains(".edu") || domain.contains(".ac.")) ? 1 : 0;
    final isOrgDomain = domain.contains(".org") ? 1 : 0;
    final isInDomain = domain.contains(".in") ? 1 : 0;
    final specialChars = RegExp(r'[^a-zA-Z0-9]').allMatches(username).length;

    return {
      "email": e,
      "username_len": usernameLen,
      "username_digits": usernameDigits,
      "username_dots": usernameDots,
      "username_underscore": usernameUnderscore,
      "username_entropy": usernameEntropy,
      "domain_len": domainLen,
      "is_common_domain": isCommonDomain,
      "is_edu_domain": isEduDomain,
      "is_org_domain": isOrgDomain,
      "is_in_domain": isInDomain,
      "special_chars": specialChars,
    };
  }

  // Heuristic risk decision (matches your Python y_train rule)
  Map<String, dynamic> _evaluateRisk(Map<String, dynamic> f) {
    final digits = (f["username_digits"] ?? 0) as int;
    final len = (f["username_len"] ?? 0) as int;
    final entropy = (f["username_entropy"] ?? 0.0) as double;
    final isRisky = (digits > 2) || (len < 6) || (entropy < 1.8);
    return {
      "email": f["email"],
      "risk_label": isRisky ? "risky" : "safe",
      "risk_probability": isRisky ? 0.85 : 0.12, // heuristic probability for UI
      "username_len": len,
      "username_digits": digits,
      "username_entropy": entropy,
      "is_common_domain": f["is_common_domain"] ?? 0,
      "is_in_domain": f["is_in_domain"] ?? 0,
    };
  }

  // ----------------------
  // Local check using Dart (no Python server needed)
  // ----------------------
  Future<void> _localCheck() async {
    final text = _controller.text.trim();
    if (text.isEmpty) {
      _showSnack("Please enter email(s)");
      return;
    }
    final emails = text.split(RegExp(r'[,\n]')).map((s) => s.trim()).where((s) => s.isNotEmpty).toList();
    setState(() { _loading = true; _results = []; _breaches = []; _error = ""; });

    final results = <Map<String, dynamic>>[];
    final skipped = <String>[];

    for (var e in emails) {
      final f = _extractFeatures(e);
      if (f == null) {
        skipped.add(e);
        continue;
      }
      final r = _evaluateRisk(f);
      results.add(r);
    }

    if (results.isEmpty) {
      setState(() { _loading = false; _error = "No valid emails provided"; });
      _showSnack("No valid emails provided.");
      return;
    }

    setState(() { _results = results; _loading = false; });
    if (skipped.isNotEmpty) _showSnack("Skipped invalid: ${skipped.join(', ')}");
  }

  // ----------------------
  // Direct LeakCheck call (no proxy). Works on mobile/desktop. Web CORS may block it.
  // ----------------------
  Future<void> _apiCheck() async {
    final text = _controller.text.trim();
    if (text.isEmpty) { _showSnack("Please enter an email"); return; }
    final email = text.split(RegExp(r'[,\n]')).map((s) => s.trim()).firstWhere((s) => s.isNotEmpty, orElse: () => "");
    if (email.isEmpty) { _showSnack("Please enter an email"); return; }

    setState(() { _loading = true; _breaches = []; _results = []; _error = ""; });

    try {
      final uri = Uri.parse("https://leakcheck.io/api/public?check=${Uri.encodeComponent(email)}");
      final resp = await http.get(uri, headers: {"User-Agent": "EmailBreachApp/1.0"},);

      if (resp.statusCode == 200) {
        final decoded = jsonDecode(resp.body);
        List<dynamic> normalized = [];

        // simple normalization heuristics
        if (decoded is Map && decoded.containsKey("sources") && decoded["sources"] is List) {
          normalized = decoded["sources"];
        } else if (decoded is List) {
          normalized = decoded;
        } else if (decoded is Map) {
          for (final k in ["result", "list", "leaks", "data"]) {
            if (decoded.containsKey(k) && decoded[k] is List) {
              normalized = decoded[k];
              break;
            }
          }
          // fallback single-object
          if (normalized.isEmpty) {
            final name = decoded["name"] ?? decoded["source"] ?? decoded["site"];
            if (name != null) normalized = [decoded];
          }
        }

        setState(() { _breaches = normalized; });
        if (_breaches.isEmpty) _showSnack("No leaks found for $email");
      } else if (resp.statusCode == 404) {
        setState(() { _breaches = []; });
        _showSnack("No leaks found for $email (404)");
      } else {
        String msg = "LeakCheck error ${resp.statusCode}";
        try { final body = jsonDecode(resp.body); msg = body["error"] ?? msg; } catch (_) {}
        _showSnack(msg);
        setState(() { _error = msg; });
      }
    } catch (e) {
      final msg = "Request failed: $e";
      _showSnack(msg);
      setState(() { _error = msg; });
    } finally {
      setState(() { _loading = false; });
    }
  }

  // ----------------------
  // UI builders
  // ----------------------
  Widget _buildResultTile(Map<String, dynamic> r) {
    final prob = r["risk_probability"] ?? 0.0;
    final label = (r["risk_label"] == "risky") ? "⚠️ Risky" : "✅ Safe";
    final color = (r["risk_label"] == "risky") ? Colors.orange : Colors.green;
    return Card(
      margin: EdgeInsets.symmetric(vertical: 6, horizontal: 12),
      child: ListTile(
        leading: CircleAvatar(backgroundColor: color, child: Text(label.contains("Risky") ? "!" : "✓", style: TextStyle(color: Colors.white))),
        title: Text(r["email"] ?? ""),
        subtitle: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          SizedBox(height: 4),
          Text("$label • Probability: ${prob.toString()}"),
          SizedBox(height: 6),
          Wrap(spacing: 8, children: [
            Chip(label: Text("len:${r['username_len']}")),
            Chip(label: Text("digits:${r['username_digits']}")),
            Chip(label: Text("entropy:${r['username_entropy']}")),
            if ((r['is_common_domain'] ?? 0) == 1) Chip(label: Text("common-domain")),
            if ((r['is_in_domain'] ?? 0) == 1) Chip(label: Text(".in")),
          ]),
        ]),
      ),
    );
  }

  Widget _buildBreachTile(Map<String, dynamic> b) {
    final name = b["name"] ?? b["domain"] ?? "Unknown";
    final domain = b["domain"];
    final breachDate = b["breach_date"];
    final description = b["description"];
    final raw = b["raw_entry"] ?? b;
    return Card(
      margin: EdgeInsets.symmetric(vertical: 6, horizontal: 12),
      child: ExpansionTile(
        leading: Icon(Icons.security, color: Colors.redAccent),
        title: Text(name.toString()),
        subtitle: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          if (domain != null) Text("Domain: $domain"),
          if (breachDate != null) Text("Date: $breachDate"),
        ]),
        children: [
          if (description != null) Padding(padding: const EdgeInsets.all(12.0), child: Text(description.toString().replaceAll(RegExp(r'<.*?>'), ''))),
          Padding(padding: const EdgeInsets.symmetric(horizontal: 12.0), child: Divider()),
          Padding(
            padding: const EdgeInsets.all(12.0),
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Text("Raw entry (debug):", style: TextStyle(fontWeight: FontWeight.bold)),
              SizedBox(height: 8),
              SingleChildScrollView(scrollDirection: Axis.horizontal, child: Text(jsonEncode(raw), style: TextStyle(fontFamily: "monospace", fontSize: 12))),
            ]),
          ),
        ],
      ),
    );
  }

  Future<void> _editBackendBaseDialog() async {
    final controller = TextEditingController(text: _backendBase);
    await showDialog(context: context, builder: (context) => AlertDialog(
      title: Text("Backend base URL"),
      content: Column(mainAxisSize: MainAxisSize.min, children: [
        Text("Set backend base URL for optional proxy usage. Examples:\n- http://10.0.2.2:5000/ (Android emulator)\n- http://192.168.1.100:5000/ (real phone)\n- https://abcd.ngrok.io/ (ngrok)"),
        SizedBox(height: 8),
        TextField(controller: controller, decoration: InputDecoration(hintText: "http://10.0.2.2:5000/")),
      ]),
      actions: [
        TextButton(onPressed: () => Navigator.of(context).pop(), child: Text("Cancel")),
        ElevatedButton(onPressed: () {
          String val = controller.text.trim();
          if (val.isNotEmpty && !val.endsWith("/")) val = "$val/";
          setState(() => _backendBase = val);
          Navigator.of(context).pop();
        }, child: Text("Save")),
      ],
    ));
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  Widget _buildTopInfo() {
    return Padding(padding: const EdgeInsets.symmetric(horizontal: 12.0), child: Column(children: [
      Row(children: [
        Expanded(child: Text("Backend: $_backendBase", style: TextStyle(fontSize: 12, color: Colors.black54))),
        TextButton(onPressed: _editBackendBaseDialog, child: Text("Change", style: TextStyle(fontSize: 12)))
      ]),
      SizedBox(height: 6),
    ]));
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
        appBar: AppBar(
          title: Text("Data Breach Detector"),
          actions: [
            IconButton(icon: Icon(Icons.refresh), tooltip: "Clear", onPressed: _loading ? null : () { _controller.clear(); setState(() { _results = []; _breaches = []; _error = ""; }); }),
            IconButton(icon: Icon(Icons.settings), tooltip: "Backend settings", onPressed: _loading ? null : _editBackendBaseDialog)
          ],
        ),
        body: SafeArea(child: Column(children: [
          Padding(padding: const EdgeInsets.all(12.0), child: TextField(controller: _controller, minLines: 2, maxLines: 6,
            decoration: InputDecoration(hintText: "Enter email(s). Example: alice@gmail.com, bob@company.com", border: OutlineInputBorder()),
          )),
          Padding(padding: const EdgeInsets.symmetric(horizontal: 12.0), child: Row(children: [
            Expanded(child: ElevatedButton.icon(icon: _loading ? SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white)) : Icon(Icons.check), label: Text(_loading ? "Please wait..." : "Predict Risk "), onPressed: _loading ? null : _localCheck)),
            SizedBox(width: 8),
            Expanded(child: ElevatedButton.icon(icon: _loading ? SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white)) : Icon(Icons.public), label: Text(_loading ? "Please wait..." : "Check Breaches"), onPressed: _loading ? null : _apiCheck)),
          ])),
          _buildTopInfo(),
          SizedBox(height: 8),
          Expanded(child: _loading ? Center(child: CircularProgressIndicator()) : _breaches.isNotEmpty ? ListView.builder(itemCount: _breaches.length, itemBuilder: (c,i) => _buildBreachTile(_breaches[i] as Map<String,dynamic>)) : (_results.isNotEmpty ? ListView.builder(itemCount: _results.length, itemBuilder: (c,i) => _buildResultTile(_results[i] as Map<String,dynamic>)) : Center(child: Text(_error.isNotEmpty ? _error : "No results yet. Use Predict Risk or Check Breaches")))),
        ]))
    );
  }
}
