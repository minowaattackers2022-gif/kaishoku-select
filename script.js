// ═══════════════════════════════════════════════════════
//  会食コンシェルジュ — Google Apps Script
//  このファイルを Google Apps Script に貼り付けてください
// ═══════════════════════════════════════════════════════

// ▼ ここを自分のスプレッドシートIDに書き換える
var SPREADSHEET_ID = '1AG3WGleERD7RAB2RaMDLRtXmRnmoSL73g9-r5-AQOX4';

// ══════════════════════════════════════
//  POST: HTMLアプリ → スプレッドシートへ書き込む
// ══════════════════════════════════════
function doPost(e) {
  try {
    var data = JSON.parse(e.postData.contents);
    var ss   = SpreadsheetApp.openById(SPREADSHEET_ID);
    var type = data.type;

    if (type === 'partner') {
      // 相手情報を書き込む
      var sheet = ss.getSheetByName('相手情報');

      // すでに同じidが登録されていれば更新、なければ追加
      var existing = findRowById(sheet, data.id);
      var row = [
        data.id,                      // A: id
        data.name         || '',       // B: 氏名
        data.company      || '',       // C: 会社名
        data.role         || '',       // D: 役職
        data.atmosphere   || '',       // E: 雰囲気
        data.ng           || '',       // F: NG
        data.memo         || '',       // G: メモ
        data.lastMet      || '',       // H: 会食日
        data.lastRestaurant || '',     // I: 利用店
        data.nextGoal     || '',       // J: 狙い
        data.createdAt    || today()   // K: 登録日
      ];

      if (existing > 0) {
        sheet.getRange(existing, 1, 1, row.length).setValues([row]);
      } else {
        sheet.appendRow(row);
      }
    }

    else if (type === 'meeting') {
      // 会食履歴を書き込む
      var sheet = ss.getSheetByName('会食履歴');
      var row = [
        data.id,
        data.date         || today(),
        data.partnerId    || '',
        data.partnerName  || '',
        data.restaurant   || '',
        data.purpose      || '',
        data.outcome      || '',
        data.topics       || '',
        data.nextGoal     || '',
        data.memo         || '',
        data.rating       || ''
      ];
      sheet.appendRow(row);
    }

    else if (type === 'sync_all') {
      // 全データを一括同期（相手情報 + 会食履歴）
      if (data.partners && data.partners.length > 0) {
        var pSheet = ss.getSheetByName('相手情報');
        // ヘッダー行を残して既存データを削除
        var lastRow = pSheet.getLastRow();
        if (lastRow > 1) pSheet.deleteRows(2, lastRow - 1);
        // 全件追加
        data.partners.forEach(function(p) {
          pSheet.appendRow([
            p.id, p.name, p.company, p.role,
            p.atmosphere, p.ng, p.memo,
            p.lastMet, p.lastRestaurant, p.nextGoal, p.createdAt
          ]);
        });
      }

      if (data.meetings && data.meetings.length > 0) {
        var mSheet = ss.getSheetByName('会食履歴');
        var lastRow = mSheet.getLastRow();
        if (lastRow > 1) mSheet.deleteRows(2, lastRow - 1);
        data.meetings.forEach(function(m) {
          mSheet.appendRow([
            m.id, m.date, m.partnerId, m.partnerName,
            m.restaurant, m.purpose, m.outcome,
            m.topics, m.nextGoal, m.memo, m.rating
          ]);
        });
      }
    }

    return jsonResponse({ success: true, message: '保存しました' });

  } catch(err) {
    return jsonResponse({ success: false, error: err.message });
  }
}

// ══════════════════════════════════════
//  GET: スプレッドシート → HTMLアプリへ読み込む
// ══════════════════════════════════════
function doGet(e) {
  try {
    var action = e.parameter.action || '';
    var ss     = SpreadsheetApp.openById(SPREADSHEET_ID);

    if (action === 'getPartners') {
      var sheet = ss.getSheetByName('相手情報');
      var data  = sheetToJson(sheet);
      return jsonResponse({ success: true, partners: data });
    }

    if (action === 'getMeetings') {
      var sheet = ss.getSheetByName('会食履歴');
      var data  = sheetToJson(sheet);
      return jsonResponse({ success: true, meetings: data });
    }

    if (action === 'getAll') {
      var pSheet = ss.getSheetByName('相手情報');
      var mSheet = ss.getSheetByName('会食履歴');
      return jsonResponse({
        success:  true,
        partners: sheetToJson(pSheet),
        meetings: sheetToJson(mSheet)
      });
    }

    // 疎通確認用
    return jsonResponse({ success: true, status: '接続OK', time: new Date().toString() });

  } catch(err) {
    return jsonResponse({ success: false, error: err.message });
  }
}

// ══════════════════════════════════════
//  内部ヘルパー関数（書き換え不要）
// ══════════════════════════════════════

// シートの全データをJSONに変換（1行目=ヘッダー）
function sheetToJson(sheet) {
  var values = sheet.getDataRange().getValues();
  if (values.length < 2) return [];
  var headers = values[0];
  return values.slice(1).map(function(row) {
    var obj = {};
    headers.forEach(function(h, i) {
      obj[h] = row[i] !== undefined ? String(row[i]) : '';
    });
    return obj;
  });
}

// idで行番号を検索（見つかったら行番号、なければ-1）
function findRowById(sheet, id) {
  var values = sheet.getDataRange().getValues();
  for (var i = 1; i < values.length; i++) {
    if (String(values[i][0]) === String(id)) return i + 1;
  }
  return -1;
}

// 今日の日付（YYYY-MM-DD）
function today() {
  return Utilities.formatDate(new Date(), 'Asia/Tokyo', 'yyyy-MM-dd');
}

// JSONレスポンスを返す
function jsonResponse(obj) {
  return ContentService
    .createTextOutput(JSON.stringify(obj))
    .setMimeType(ContentService.MimeType.JSON);
}
