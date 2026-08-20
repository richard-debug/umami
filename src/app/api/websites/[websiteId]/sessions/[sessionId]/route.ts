import { getBlocklist } from '@/lib/blocklist';
import { parseRequest } from '@/lib/request';
import { json, unauthorized } from '@/lib/response';
import { addIpReputation } from '@/lib/session-reputation';
import { canViewWebsiteSection } from '@/permissions';
import { getWebsiteSession } from '@/queries/sql';

export async function GET(
  request: Request,
  { params }: { params: Promise<{ websiteId: string; sessionId: string }> },
) {
  const { auth, error } = await parseRequest(request);

  if (error) {
    return error();
  }

  const { websiteId, sessionId } = await params;

  if (
    !(await canViewWebsiteSection(auth, websiteId, ['sessions', 'events', 'realtime', 'revenue']))
  ) {
    return unauthorized();
  }

  const data = await getWebsiteSession(websiteId, sessionId);

  if (!data) {
    return json(data);
  }

  const blocklist = await getBlocklist();

  return json(addIpReputation(data, blocklist));
}
